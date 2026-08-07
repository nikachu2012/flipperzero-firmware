#include "felica_log.h"

#include <furi_hal_rtc.h>
#include <storage/storage.h>

#include <stdarg.h>
#include <stdio.h>

#define TAG "FelicaListener"

/** Folder and file the trace is written to. Every emulation session appends to
 * the same file so repeated attempts against a reader end up in one place. */
#define FELICA_LOG_FOLDER         EXT_PATH("nfc/felica_logs")
#define FELICA_LOG_FILE_PATH      FELICA_LOG_FOLDER "/felica_emulation.log"
#define FELICA_LOG_FILE_PREV_PATH FELICA_LOG_FOLDER "/felica_emulation.log.prev"

/** The log is rotated to .prev once it grows past this. */
#define FELICA_LOG_SIZE_MAX (512UL * 1024UL)

/** Bytes buffered between the NFC thread and the writer thread. Sized to hold a
 * burst of several full 256-byte frames (~530 chars each once hex-encoded) so a
 * slow SD write does not cost entries. */
#define FELICA_LOG_STREAM_SIZE (8192U)

/** Largest single formatted line. A 256-byte frame is 512 hex chars plus the
 * timestamp/direction prefix. */
#define FELICA_LOG_LINE_SIZE (640U)

/** Frame bytes beyond this are elided; keeps the line bound above honest. */
#define FELICA_LOG_FRAME_BYTES_MAX (256U)

/** How long the writer thread waits for data before looping to check for stop. */
#define FELICA_LOG_RECEIVE_TIMEOUT_MS (250U)

/** Entries are pushed with a zero timeout so the RF path never blocks. */
#define FELICA_LOG_SEND_TIMEOUT_MS (0U)

typedef struct {
    FuriStreamBuffer* stream;
    FuriThread* thread;
    uint32_t session_count;
    uint32_t start_tick;
    uint32_t dropped;
    bool running;
} FelicaLog;

static FelicaLog* felica_log = NULL;
static bool felica_log_enabled = true;

// ---------------------------------------------------------------------------
// Writer thread: the only context that touches storage
// ---------------------------------------------------------------------------

/** Moves the current log aside once it grows past @ref FELICA_LOG_SIZE_MAX, so the
 * trace never fills the SD card while the previous run stays available. */
static void felica_log_rotate(Storage* storage) {
    if(storage_common_stat(storage, FELICA_LOG_FILE_PATH, NULL) != FSE_OK) return;

    uint64_t size = 0;
    File* file = storage_file_alloc(storage);
    if(storage_file_open(file, FELICA_LOG_FILE_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        size = storage_file_size(file);
        storage_file_close(file);
    }
    storage_file_free(file);

    if(size < FELICA_LOG_SIZE_MAX) return;

    storage_common_remove(storage, FELICA_LOG_FILE_PREV_PATH);
    storage_common_rename(storage, FELICA_LOG_FILE_PATH, FELICA_LOG_FILE_PREV_PATH);
}

static File* felica_log_open_file(Storage* storage) {
    if(!storage_simply_mkdir(storage, FELICA_LOG_FOLDER)) {
        FURI_LOG_E(TAG, "Failed to create " FELICA_LOG_FOLDER);
        return NULL;
    }

    felica_log_rotate(storage);

    File* file = storage_file_alloc(storage);
    if(!storage_file_open(file, FELICA_LOG_FILE_PATH, FSAM_WRITE, FSOM_OPEN_APPEND)) {
        FURI_LOG_E(TAG, "Failed to open " FELICA_LOG_FILE_PATH);
        storage_file_free(file);
        return NULL;
    }

    // Sessions are appended to one file, so each needs a wall-clock banner: the
    // per-entry timestamps are relative to the start of the session.
    DateTime dt;
    furi_hal_rtc_get_datetime(&dt);
    FuriString* banner = furi_string_alloc_printf(
        "\n=== FeliCa emulation session %04u-%02u-%02u %02u:%02u:%02u ===\n",
        dt.year,
        dt.month,
        dt.day,
        dt.hour,
        dt.minute,
        dt.second);
    storage_file_write(file, furi_string_get_cstr(banner), furi_string_size(banner));
    furi_string_free(banner);

    return file;
}

static int32_t felica_log_writer_thread(void* context) {
    FelicaLog* instance = context;

    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = NULL;
    uint8_t chunk[512];

    while(true) {
        const size_t received = furi_stream_buffer_receive(
            instance->stream,
            chunk,
            sizeof(chunk),
            furi_ms_to_ticks(FELICA_LOG_RECEIVE_TIMEOUT_MS));

        if(received > 0) {
            // Open the file only once there is something to put in it, so an
            // emulation session that never sees a reader touches no storage.
            if(!file) file = felica_log_open_file(storage);
            if(file) storage_file_write(file, chunk, received);
        } else if(!instance->running) {
            // No data left and stop requested: the buffer is drained.
            break;
        } else if(file) {
            // Flush periodically so a crash or a yanked battery keeps the trace.
            storage_file_sync(file);
        }
    }

    if(file) {
        storage_file_close(file);
        storage_file_free(file);
    }
    furi_record_close(RECORD_STORAGE);

    return 0;
}

// ---------------------------------------------------------------------------
// Producer side
// ---------------------------------------------------------------------------

static void felica_log_write_line(const char* line, size_t len) {
    FelicaLog* instance = felica_log;
    if(!instance) return;

    const size_t sent = furi_stream_buffer_send(
        instance->stream, line, len, furi_ms_to_ticks(FELICA_LOG_SEND_TIMEOUT_MS));
    if(sent != len) instance->dropped++;
}

/** Formats the shared "[seconds.millis] " prefix, returns its length. */
static size_t felica_log_format_prefix(char* out, size_t out_size) {
    const uint32_t elapsed_ticks = furi_get_tick() - felica_log->start_tick;
    const uint32_t elapsed_ms = elapsed_ticks * 1000UL / furi_kernel_get_tick_frequency();
    const int len = snprintf(
        out,
        out_size,
        "[%6lu.%03lu] ",
        (unsigned long)(elapsed_ms / 1000),
        (unsigned long)(elapsed_ms % 1000));
    return (len < 0) ? 0 : (size_t)len;
}

static size_t felica_log_format_hex(char* out, size_t out_size, const uint8_t* data, size_t len) {
    // A nibble table rather than one snprintf per byte: this runs on the path between
    // receiving a command and answering it, where a 256-byte frame would otherwise
    // cost 256 snprintf calls against the reader's response deadline.
    static const char nibble[] = "0123456789ABCDEF";
    size_t pos = 0;
    const size_t printed = (len > FELICA_LOG_FRAME_BYTES_MAX) ? FELICA_LOG_FRAME_BYTES_MAX : len;

    for(size_t i = 0; (i < printed) && (pos + 3 <= out_size); i++) {
        out[pos] = nibble[data[i] >> 4];
        out[pos + 1] = nibble[data[i] & 0x0F];
        pos += 2;
    }
    if(printed < len) {
        pos += snprintf(out + pos, out_size - pos, "...");
    }
    return pos;
}

/** Formats one "<prefix> <tag> <message>" line and queues it. */
static void felica_log_write_message(const char* tag, const char* message) {
    if(!felica_log) return;

    char line[FELICA_LOG_LINE_SIZE];
    size_t pos = felica_log_format_prefix(line, sizeof(line));
    if(pos >= sizeof(line) - 2) return;

    const int written = snprintf(line + pos, sizeof(line) - pos, "%s %s", tag, message);
    if(written > 0) {
        const size_t room = sizeof(line) - pos - 1;
        pos += ((size_t)written < room) ? (size_t)written : room;
    }
    line[pos++] = '\n';

    felica_log_write_line(line, pos);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

void felica_log_set_enabled(bool enabled) {
    felica_log_enabled = enabled;
}

bool felica_log_is_enabled(void) {
    return felica_log_enabled;
}

void felica_log_session_start(void) {
    if(!felica_log_enabled) return;

    if(felica_log) {
        felica_log->session_count++;
        return;
    }

    FelicaLog* instance = malloc(sizeof(FelicaLog));
    instance->stream = furi_stream_buffer_alloc(FELICA_LOG_STREAM_SIZE, 1);
    instance->session_count = 1;
    instance->start_tick = furi_get_tick();
    instance->dropped = 0;
    instance->running = true;

    instance->thread =
        furi_thread_alloc_ex("FelicaLogWriter", 2 * 1024, felica_log_writer_thread, instance);
    furi_thread_set_priority(instance->thread, FuriThreadPriorityLow);

    felica_log = instance;
    furi_thread_start(instance->thread);
}

void felica_log_session_stop(void) {
    FelicaLog* instance = felica_log;
    if(!instance) return;

    if(--instance->session_count > 0) return;

    if(instance->dropped > 0) {
        felica_log_event("%lu entries dropped (log buffer full)", instance->dropped);
    }

    // Stop publishing before tearing down so late calls from other threads
    // become no-ops rather than touching freed memory.
    felica_log = NULL;
    instance->running = false;

    furi_thread_join(instance->thread);
    furi_thread_free(instance->thread);
    furi_stream_buffer_free(instance->stream);
    free(instance);
}

void felica_log_frame(FelicaLogDirection direction, const uint8_t* data, size_t len) {
    if(!felica_log) return;

    char line[FELICA_LOG_LINE_SIZE];
    size_t pos = felica_log_format_prefix(line, sizeof(line));
    pos += snprintf(
        line + pos,
        sizeof(line) - pos,
        "%s %3u ",
        (direction == FelicaLogDirectionTx) ? "-->" : "<--",
        (unsigned)len);
    if(pos >= sizeof(line) - 1) return;

    if(data) pos += felica_log_format_hex(line + pos, sizeof(line) - pos - 1, data, len);
    line[pos++] = '\n';

    felica_log_write_line(line, pos);
}

void felica_log_buffer(const char* label, const uint8_t* data, size_t len) {
    if(!felica_log) return;

    char line[FELICA_LOG_LINE_SIZE];
    size_t pos = felica_log_format_prefix(line, sizeof(line));
    pos += snprintf(line + pos, sizeof(line) - pos, "    %s (%u): ", label, (unsigned)len);
    if(pos >= sizeof(line) - 1) return;

    if(data) pos += felica_log_format_hex(line + pos, sizeof(line) - pos - 1, data, len);
    line[pos++] = '\n';

    felica_log_write_line(line, pos);
}

void felica_log_event(const char* format, ...) {
    if(!felica_log) return;

    char message[FELICA_LOG_LINE_SIZE / 2];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    felica_log_write_message("   ", message);
}

void felica_log_error(const char* format, ...) {
    char message[FELICA_LOG_LINE_SIZE / 2];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    FURI_LOG_E(TAG, "%s", message);
    felica_log_write_message("ERR", message);
}
