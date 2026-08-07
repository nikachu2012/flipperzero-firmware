/**
 * @file felica_log.h
 * @brief FeliCa emulation trace log.
 *
 * Records every FeliCa frame exchanged while emulating a card (both
 * directions) and every protocol error to a file on the SD card, so failed
 * transactions with real readers can be analysed afterwards.
 *
 * Writing to storage from the NFC worker thread would add unbounded latency to
 * the RF exchange and make readers time out mid-transaction. Therefore the
 * logging calls below only format the entry and push it into a stream buffer;
 * a dedicated writer thread drains that buffer into the file. If the buffer is
 * full the entry is dropped (and counted) instead of blocking the caller.
 */
#pragma once

#include <furi.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    FelicaLogDirectionRx, /**< Frame received from the reader. */
    FelicaLogDirectionTx, /**< Frame transmitted to the reader. */
} FelicaLogDirection;

/** Enable or disable logging globally.
 *
 * Disabling does not close an already running session; it only prevents new
 * sessions from starting and silently drops further entries.
 *
 * @param[in] enabled  true to allow logging.
 */
void felica_log_set_enabled(bool enabled);

/** @return true if logging is allowed. */
bool felica_log_is_enabled(void);

/** Start a logging session, called when the FeliCa listener is allocated.
 *
 * Reference counted. The log file itself is opened lazily by the writer thread
 * when the first entry arrives, so a session without traffic touches no
 * storage.
 */
void felica_log_session_start(void);

/** End a logging session opened with @ref felica_log_session_start.
 *
 * Blocks until the writer thread has flushed and closed the file when the last
 * reference is released.
 */
void felica_log_session_stop(void);

/** Log a complete frame in hex, exactly as it appears on the wire.
 *
 * @param[in] direction  frame direction.
 * @param[in] data       frame bytes, may be NULL if len is 0.
 * @param[in] len        frame length in bytes.
 */
void felica_log_frame(FelicaLogDirection direction, const uint8_t* data, size_t len);

/** Log a labelled hex buffer, e.g. a decrypted payload or a MAC. */
void felica_log_buffer(const char* label, const uint8_t* data, size_t len);

/** Log an informational event. */
void felica_log_event(const char* format, ...) _ATTRIBUTE((__format__(__printf__, 1, 2)));

/** Log an error. Also mirrored to the furi log at error level. */
void felica_log_error(const char* format, ...) _ATTRIBUTE((__format__(__printf__, 1, 2)));

#ifdef __cplusplus
}
#endif
