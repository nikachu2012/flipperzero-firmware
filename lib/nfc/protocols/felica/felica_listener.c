#include "felica_listener_i.h"

#include "nfc/protocols/nfc_listener_base.h"
#include <nfc/helpers/felica_crc.h>
#include <furi_hal_nfc.h>
#include <furi_hal_random.h>

#define FELICA_LISTENER_MAX_BUFFER_SIZE     (256)
#define FELICA_LISTENER_RESPONSE_POLLING    (0x01U)
#define FELICA_LISTENER_RESPONSE_CODE_READ  (0x07)
#define FELICA_LISTENER_RESPONSE_CODE_WRITE (0x09)

#define FELICA_LISTENER_REQUEST_NONE        (0x00U)
#define FELICA_LISTENER_REQUEST_SYSTEM_CODE (0x01U)
#define FELICA_LISTENER_REQUEST_PERFORMANCE (0x02U)

#define FELICA_LISTENER_SYSTEM_CODE_NDEF  (__builtin_bswap16(0x12FCU))
#define FELICA_LISTENER_SYSTEM_CODE_LITES (__builtin_bswap16(0x88B4U))

#define FELICA_LISTENER_PERFORMANCE_VALUE (__builtin_bswap16(0x0083U))

#define TAG "FelicaListener"

static void felica_listener_log_hex(const char* label, const uint8_t* data, size_t len) {
    size_t n = len < FELICA_LISTENER_MAX_BUFFER_SIZE ? len : FELICA_LISTENER_MAX_BUFFER_SIZE;
    char hex[FELICA_LISTENER_MAX_BUFFER_SIZE * 2 + 1];
    for(size_t i = 0; i < n; i++) {
        snprintf(hex + i * 2, 3, "%02X", data[i]);
    }
    hex[n * 2] = '\0';
    FURI_LOG_D(TAG, "%s (%zu): %s", label, len, hex);
}

FelicaListener* felica_listener_alloc(Nfc* nfc, FelicaData* data) {
    furi_assert(nfc);
    furi_assert(data);

    FelicaListener* instance = malloc(sizeof(FelicaListener));
    instance->nfc = nfc;
    instance->data = data;
    instance->tx_buffer = bit_buffer_alloc(FELICA_LISTENER_MAX_BUFFER_SIZE);
    instance->rx_buffer = bit_buffer_alloc(FELICA_LISTENER_MAX_BUFFER_SIZE);

    mbedtls_des3_init(&instance->auth.des_context);
    nfc_set_fdt_listen_fc(instance->nfc, FELICA_FDT_LISTEN_FC);

    memcpy(instance->mc_shadow.data, instance->data->data.fs.mc.data, FELICA_DATA_BLOCK_SIZE);
    instance->data->data.fs.state.data[0] = 0;
    instance->mode = FELICA_LISTENER_MODE_UNAUTHENTICATED;
    instance->current_system_idx = 0;
    nfc_config(instance->nfc, NfcModeListener, NfcTechFelica);

    // nfc_listener_alloc() works on a copy of the loaded NFC data. Log the same
    // boundary entries here to catch stale firmware or corruption during that copy.
    if(simple_array_get_count(data->systems) > 0) {
        const FelicaSystem* system = simple_array_cget(data->systems, 0);
        const uint32_t public_block_count = simple_array_get_count(system->public_blocks);
        const uint16_t diagnostic_entries[] = {0x19, 0x1E};
        FURI_LOG_I(TAG, "PBHEX3 listener active: blocks=%lu", public_block_count);
        for(size_t i = 0; i < COUNT_OF(diagnostic_entries); i++) {
            const uint16_t entry = diagnostic_entries[i];
            if(entry >= public_block_count) continue;
            const FelicaPublicBlock* block = simple_array_cget(system->public_blocks, entry);
            FURI_LOG_I(
                TAG,
                "PBHEX3 listener: entry=%04X service=%04X block=%02X",
                entry,
                block->service_code,
                block->block_idx);
        }
    }

    // The PMm is emulated exactly as it was read from the NFC file, including the
    // response-time bytes 2-7.
    const uint16_t system_code = *(uint16_t*)data->data.fs.sys_c.data;
    nfc_felica_listener_set_sensf_res_data(
        nfc, data->idm.data, sizeof(data->idm), data->pmm.data, sizeof(data->pmm), system_code);

    return instance;
}

void felica_listener_free(FelicaListener* instance) {
    furi_assert(instance);
    furi_assert(instance->tx_buffer);

    bit_buffer_free(instance->tx_buffer);
    bit_buffer_free(instance->rx_buffer);
    free(instance);
}

void felica_listener_set_callback(
    FelicaListener* listener,
    NfcGenericCallback callback,
    void* context) {
    UNUSED(listener);
    UNUSED(callback);
    UNUSED(context);
}

const FelicaData* felica_listener_get_data(const FelicaListener* instance) {
    furi_assert(instance);
    furi_assert(instance->data);

    return instance->data;
}

static FelicaError felica_listener_command_handler_read(
    FelicaListener* instance,
    const FelicaListenerGenericRequest* const generic_request) {
    const FelicaListenerReadRequest* request = (FelicaListenerReadRequest*)generic_request;
    FURI_LOG_D(TAG, "Read cmd");

    FelicaListenerReadCommandResponse* resp = malloc(
        sizeof(FelicaCommandResponseHeader) + 1 +
        FELICA_LISTENER_READ_BLOCK_COUNT_MAX * FELICA_DATA_BLOCK_SIZE);

    resp->header.response_code = FELICA_LISTENER_RESPONSE_CODE_READ;
    resp->header.idm = request->base.header.idm;
    resp->header.length = sizeof(FelicaCommandResponseHeader);

    if(felica_listener_validate_read_request_and_set_sf(instance, request, &resp->header)) {
        resp->block_count = request->base.header.block_count;
        resp->header.length++;
    } else {
        resp->block_count = 0;
    }

    instance->mac_calc_start = 0;
    memset(instance->requested_blocks, 0, sizeof(instance->requested_blocks));
    const FelicaBlockListElement* item =
        felica_listener_block_list_item_get_first(instance, request);
    for(uint8_t i = 0; i < resp->block_count; i++) {
        instance->requested_blocks[i] = item->block_number;
        FelicaCommanReadBlockHandler handler =
            felica_listener_get_read_block_handler(item->block_number);

        handler(instance, item->block_number, i, resp);

        item = felica_listener_block_list_item_get_next(instance, item);
    }

    bit_buffer_reset(instance->tx_buffer);
    bit_buffer_append_bytes(instance->tx_buffer, (uint8_t*)resp, resp->header.length);
    free(resp);

    return felica_listener_frame_exchange(instance, instance->tx_buffer);
}

static FelicaError felica_listener_command_handler_write(
    FelicaListener* instance,
    const FelicaListenerGenericRequest* const generic_request) {
    FURI_LOG_D(TAG, "Write cmd");

    const FelicaListenerWriteRequest* request = (FelicaListenerWriteRequest*)generic_request;
    const FelicaListenerWriteBlockData* data_ptr =
        felica_listener_get_write_request_data_pointer(instance, generic_request);

    FelicaListenerWriteCommandResponse* resp = malloc(sizeof(FelicaListenerWriteCommandResponse));

    resp->response_code = FELICA_LISTENER_RESPONSE_CODE_WRITE;
    resp->idm = request->base.header.idm;
    resp->length = sizeof(FelicaListenerWriteCommandResponse);

    if(felica_listener_validate_write_request_and_set_sf(instance, request, data_ptr, resp)) {
        const FelicaBlockListElement* item =
            felica_listener_block_list_item_get_first(instance, request);
        for(uint8_t i = 0; i < request->base.header.block_count; i++) {
            FelicaCommandWriteBlockHandler handler =
                felica_listener_get_write_block_handler(item->block_number);

            handler(instance, item->block_number, &data_ptr->blocks[i]);

            item = felica_listener_block_list_item_get_next(instance, item);
        }
        felica_wcnt_increment(instance->data);
    }

    bit_buffer_reset(instance->tx_buffer);
    bit_buffer_append_bytes(instance->tx_buffer, (uint8_t*)resp, resp->length);
    free(resp);

    return felica_listener_frame_exchange(instance, instance->tx_buffer);
}

// Returns the currently selected System (instance->current_system_idx), or NULL if
// there is none - callers must not assume System 0 is the active one, since Polling
// with a specific System Code can switch this mid-session.
static const FelicaSystem* felica_listener_get_current_system(const FelicaListener* instance) {
    uint32_t system_count = simple_array_get_count(instance->data->systems);
    if(instance->current_system_idx >= system_count) return NULL;
    return simple_array_cget(instance->data->systems, instance->current_system_idx);
}

static FelicaSystem* felica_listener_get_current_system_mut(FelicaListener* instance) {
    uint32_t system_count = simple_array_get_count(instance->data->systems);
    if(instance->current_system_idx >= system_count) return NULL;
    return simple_array_get(instance->data->systems, instance->current_system_idx);
}

// Two Service Codes that share the same Service Number (bits 15:6) but differ only in
// Attribute (bits 5:0, e.g. a Read/Write code and its Read Only "shadow" code) address
// the same physical block storage. A dump commonly only captures block data under one
// of the variants, so lookups must match by Service Number rather than the exact code
// the reader authenticated with, or a legitimate read/write via the sibling code fails.
static const FelicaPublicBlock*
    felica_std_find_public_block(const FelicaSystem* system, uint16_t svc_code, uint16_t blk_num) {
    uint32_t pb_count = simple_array_get_count(system->public_blocks);
    const FelicaPublicBlock* sibling = NULL;
    for(uint32_t j = 0; j < pb_count; j++) {
        const FelicaPublicBlock* pb = simple_array_cget(system->public_blocks, j);
        if(pb->block_idx != blk_num) continue;
        if(pb->service_code == svc_code) return pb;
        if(!sibling && (pb->service_code >> 6) == (svc_code >> 6)) sibling = pb;
    }
    return sibling;
}

static FelicaPublicBlock*
    felica_std_find_public_block_mut(FelicaSystem* system, uint16_t svc_code, uint16_t blk_num) {
    uint32_t pb_count = simple_array_get_count(system->public_blocks);
    FelicaPublicBlock* sibling = NULL;
    for(uint32_t j = 0; j < pb_count; j++) {
        FelicaPublicBlock* pb = simple_array_get(system->public_blocks, j);
        if(pb->block_idx != blk_num) continue;
        if(pb->service_code == svc_code) return pb;
        if(!sibling && (pb->service_code >> 6) == (svc_code >> 6)) sibling = pb;
    }
    return sibling;
}

// A successful response consists of the command response header, one block-count
// byte, and 16 bytes per block. Leave room for the CRC appended before transmit.
#define FELICA_STANDARD_READ_RESPONSE_HEADER_SIZE \
    (sizeof(FelicaCommandResponseHeader) + sizeof(uint8_t))
#define FELICA_STANDARD_READ_BLOCK_MAX                    \
    ((FELICA_LISTENER_MAX_BUFFER_SIZE - FELICA_CRC_SIZE - \
      FELICA_STANDARD_READ_RESPONSE_HEADER_SIZE) /        \
     FELICA_DATA_BLOCK_SIZE)

static FelicaError felica_listener_command_handler_standard_read(
    FelicaListener* instance,
    const FelicaListenerGenericRequest* const generic_request) {
    const uint8_t* raw = (const uint8_t*)generic_request;
    uint8_t service_num = raw[10];
    if(service_num == 0 || service_num > 16) {
        return FelicaErrorProtocol;
    }

    uint16_t service_codes[16];
    for(uint8_t i = 0; i < service_num; i++) {
        service_codes[i] = (uint16_t)(raw[11 + i * 2] | ((uint16_t)raw[12 + i * 2] << 8));
    }

    const uint8_t block_count = raw[11 + service_num * 2];
    const uint8_t* bptr = raw + 12 + service_num * 2;

    const FelicaSystem* system = felica_listener_get_current_system(instance);

    uint8_t sf1 = 0x00, sf2 = 0x00;
    uint8_t block_data[FELICA_STANDARD_READ_BLOCK_MAX][FELICA_DATA_BLOCK_SIZE];
    uint8_t actual_block_count = 0;

    if((block_count == 0) || (block_count > FELICA_STANDARD_READ_BLOCK_MAX)) {
        sf1 = 0xFF;
        sf2 = 0xA2;
    }

    for(uint8_t i = 0; (sf1 == 0) && (i < block_count); i++) {
        uint8_t svc_idx = bptr[0] & 0x0F;
        bool is_2byte = (bptr[0] >> 7) != 0;
        uint8_t blk_num;

        if(is_2byte) {
            blk_num = bptr[1];
            bptr += 2;
        } else {
            blk_num = bptr[1]; // lower byte of LE block number; upper byte (bptr[2]) must be 0
            bptr += 3;
        }

        if(svc_idx >= service_num || !system) {
            sf1 = 0xFF;
            sf2 = 0xA8;
            break;
        }

        uint16_t svc_code = service_codes[svc_idx];
        const FelicaPublicBlock* pb = felica_std_find_public_block(system, svc_code, blk_num);
        bool found = pb != NULL;
        if(found) {
            memcpy(block_data[actual_block_count], pb->block.data, FELICA_DATA_BLOCK_SIZE);
        }

        if(!found) {
            sf1 = 0xFF;
            sf2 = 0xA8;
            break;
        }
        actual_block_count++;
    }

    size_t resp_size =
        (sf1 == 0) ? (size_t)(12 + 1 + actual_block_count * FELICA_DATA_BLOCK_SIZE) : 12;
    uint8_t* resp_buf = malloc(resp_size);
    resp_buf[0] = (uint8_t)resp_size;
    resp_buf[1] = FELICA_LISTENER_RESPONSE_CODE_READ;
    const FelicaIDm current_idm = felica_listener_get_current_idm(instance);
    memcpy(resp_buf + 2, current_idm.data, 8);
    resp_buf[10] = sf1;
    resp_buf[11] = sf2;
    if(sf1 == 0) {
        resp_buf[12] = actual_block_count;
        for(uint8_t i = 0; i < actual_block_count; i++) {
            memcpy(
                resp_buf + 13 + i * FELICA_DATA_BLOCK_SIZE, block_data[i], FELICA_DATA_BLOCK_SIZE);
        }
    }

    bit_buffer_reset(instance->tx_buffer);
    bit_buffer_append_bytes(instance->tx_buffer, resp_buf, resp_size);
    free(resp_buf);

    return felica_listener_frame_exchange(instance, instance->tx_buffer);
}

static FelicaError felica_listener_command_handler_standard_write(
    FelicaListener* instance,
    const FelicaListenerGenericRequest* const generic_request) {
    const uint8_t* raw = (const uint8_t*)generic_request;
    uint8_t service_num = raw[10];
    if(service_num == 0 || service_num > 16) {
        return FelicaErrorProtocol;
    }

    uint16_t service_codes[16];
    for(uint8_t i = 0; i < service_num; i++) {
        service_codes[i] = (uint16_t)(raw[11 + i * 2] | ((uint16_t)raw[12 + i * 2] << 8));
    }

    uint8_t block_count = raw[11 + service_num * 2];
    const uint8_t* bptr = raw + 12 + service_num * 2;

    FelicaSystem* system = felica_listener_get_current_system_mut(instance);

    uint8_t sf1 = 0x00, sf2 = 0x00;

    struct {
        uint16_t svc_code;
        uint8_t blk_num;
    } targets[16];
    uint8_t valid_count = 0;

    for(uint8_t i = 0; i < block_count && i < 16; i++) {
        uint8_t svc_idx = bptr[0] & 0x0F;
        bool is_2byte = (bptr[0] >> 7) != 0;
        uint8_t blk_num;

        if(is_2byte) {
            blk_num = bptr[1];
            bptr += 2;
        } else {
            blk_num = bptr[1];
            bptr += 3;
        }

        if(svc_idx >= service_num || !system) {
            sf1 = 0xFF;
            sf2 = 0xA8;
            break;
        }

        uint16_t svc_code = service_codes[svc_idx];

        uint32_t svc_count = simple_array_get_count(system->services);
        bool svc_found = false;
        for(uint32_t k = 0; k < svc_count; k++) {
            const FelicaService* svc = simple_array_cget(system->services, k);
            if(svc->code == svc_code) {
                svc_found = true;
                if(svc->attr & FELICA_SERVICE_ATTRIBUTE_READ_ONLY) {
                    sf1 = 0xFF;
                    sf2 = 0xA6;
                }
                break;
            }
        }
        if(!svc_found || sf1 != 0) break;

        targets[i].svc_code = svc_code;
        targets[i].blk_num = blk_num;
        valid_count++;
    }

    if(sf1 == 0 && system) {
        for(uint8_t i = 0; i < valid_count; i++) {
            FelicaPublicBlock* pb =
                felica_std_find_public_block_mut(system, targets[i].svc_code, targets[i].blk_num);
            bool found = pb != NULL;
            if(found) {
                memcpy(pb->block.data, bptr + i * FELICA_DATA_BLOCK_SIZE, FELICA_DATA_BLOCK_SIZE);
            }
            if(!found) {
                sf1 = 0xFF;
                sf2 = 0xA8;
                break;
            }
        }
    }

    uint8_t resp_buf[12];
    resp_buf[0] = 12;
    resp_buf[1] = FELICA_LISTENER_RESPONSE_CODE_WRITE;
    const FelicaIDm current_idm = felica_listener_get_current_idm(instance);
    memcpy(resp_buf + 2, current_idm.data, 8);
    resp_buf[10] = sf1;
    resp_buf[11] = sf2;

    bit_buffer_reset(instance->tx_buffer);
    bit_buffer_append_bytes(instance->tx_buffer, resp_buf, 12);

    return felica_listener_frame_exchange(instance, instance->tx_buffer);
}

static FelicaError felica_listener_command_handler_request_response(
    FelicaListener* instance,
    const FelicaListenerGenericRequest* const generic_request) {
    UNUSED(generic_request);

    // Response: length(1) + RC(1) + IDm(8) + mode(1) = 11 bytes
    const size_t resp_size = 11;
    uint8_t resp_buf[resp_size];
    resp_buf[0] = (uint8_t)resp_size;
    resp_buf[1] = FELICA_CMD_REQUEST_RESPONSE_RESP;
    const FelicaIDm current_idm = felica_listener_get_current_idm(instance);
    memcpy(resp_buf + 2, current_idm.data, 8);
    resp_buf[10] = instance->mode;

    bit_buffer_reset(instance->tx_buffer);
    bit_buffer_append_bytes(instance->tx_buffer, resp_buf, resp_size);
    return felica_listener_frame_exchange(instance, instance->tx_buffer);
}

static FelicaError felica_listener_command_handler_request_service(
    FelicaListener* instance,
    const FelicaListenerGenericRequest* const generic_request) {
    const uint8_t* raw = (const uint8_t*)generic_request;
    uint8_t n = raw[10];
    FURI_LOG_D(TAG, "Request Service cmd, n=%u", n);

    // Clamp: response is 11 + 2n bytes; tx buffer is FELICA_LISTENER_MAX_BUFFER_SIZE bytes (incl. 2-byte CRC)
    const uint8_t n_max = (FELICA_LISTENER_MAX_BUFFER_SIZE - 2 - 11) / 2;
    if(n > n_max) n = n_max;

    const FelicaSystem* system = felica_listener_get_current_system(instance);

    size_t resp_size = 11 + (size_t)n * 2;
    uint8_t* resp_buf = malloc(resp_size);
    resp_buf[0] = (uint8_t)resp_size;
    resp_buf[1] = FELICA_CMD_REQUEST_SERVICE_RESP;
    const FelicaIDm current_idm = felica_listener_get_current_idm(instance);
    memcpy(resp_buf + 2, current_idm.data, 8);
    resp_buf[10] = n;

    for(uint8_t i = 0; i < n; i++) {
        uint16_t req_code = (uint16_t)(raw[11 + i * 2] | ((uint16_t)raw[12 + i * 2] << 8));
        uint16_t kv = 0xFFFF;

        if(req_code == 0xFFFF) {
            kv = system ? system->key_version : 0xFFFF;
        } else if(system) {
            uint32_t area_count = simple_array_get_count(system->areas);
            for(uint32_t j = 0; j < area_count; j++) {
                const FelicaArea* area = simple_array_cget(system->areas, j);
                if(area->code == req_code) {
                    kv = area->key_version;
                    break;
                }
            }
            if(kv == 0xFFFF) {
                uint32_t svc_count = simple_array_get_count(system->services);
                for(uint32_t j = 0; j < svc_count; j++) {
                    const FelicaService* svc = simple_array_cget(system->services, j);
                    if(svc->code == req_code) {
                        kv = svc->key_version;
                        break;
                    }
                }
            }
        }

        resp_buf[11 + i * 2] = (uint8_t)(kv & 0xFF);
        resp_buf[12 + i * 2] = (uint8_t)(kv >> 8);
    }

    bit_buffer_reset(instance->tx_buffer);
    bit_buffer_append_bytes(instance->tx_buffer, resp_buf, resp_size);
    free(resp_buf);

    return felica_listener_frame_exchange(instance, instance->tx_buffer);
}

static FelicaError felica_listener_command_handler_search_service_code(
    FelicaListener* instance,
    const FelicaListenerGenericRequest* const generic_request) {
    const uint8_t* raw_req = (const uint8_t*)generic_request;
    uint16_t counter = (uint16_t)(raw_req[10] | ((uint16_t)raw_req[11] << 8));
    FURI_LOG_D(TAG, "Search Service Code cmd, counter=%04X", counter);

    const FelicaSystem* system = felica_listener_get_current_system(instance);

    uint32_t area_count = system ? simple_array_get_count(system->areas) : 0;
    uint32_t service_count = system ? simple_array_get_count(system->services) : 0;

    uint32_t pos = 0;
    uint32_t ai = 0;
    uint32_t si = 0;
    bool found = false;
    bool is_area = false;
    uint16_t code_lo = 0xFFFF;
    uint16_t code_hi = 0;

    while(true) {
        bool pick_area = false;
        if(ai < area_count) {
            const FelicaArea* a = simple_array_cget(system->areas, ai);
            pick_area = (si >= a->first_idx);
        }

        if(pick_area) {
            if(pos == counter) {
                const FelicaArea* a = simple_array_cget(system->areas, ai);
                is_area = true;
                code_lo = a->code;
                code_hi = a->end_code;
                found = true;
                break;
            }
            ai++;
            pos++;
        } else if(si < service_count) {
            if(pos == counter) {
                const FelicaService* svc = simple_array_cget(system->services, si);
                is_area = false;
                code_lo = svc->code;
                found = true;
                break;
            }
            si++;
            pos++;
        } else {
            break;
        }
    }

    uint8_t resp_data_size = (found && is_area) ? 4 : 2;
    size_t resp_size = sizeof(FelicaCommandHeaderRaw) + resp_data_size;

    uint8_t* resp_buf = malloc(resp_size);
    FelicaListServiceCommandResponse* resp = (FelicaListServiceCommandResponse*)resp_buf;

    resp->header.length = (uint8_t)resp_size;
    resp->header.command = FELICA_CMD_LIST_SERVICE_CODE_RESP;
    resp->header.idm = felica_listener_get_current_idm(instance);

    if(found && is_area) {
        resp->data[0] = (uint8_t)(code_lo & 0xFF);
        resp->data[1] = (uint8_t)(code_lo >> 8);
        resp->data[2] = (uint8_t)(code_hi & 0xFF);
        resp->data[3] = (uint8_t)(code_hi >> 8);
    } else {
        // Service code or end-of-list (0xFFFF)
        resp->data[0] = (uint8_t)(code_lo & 0xFF);
        resp->data[1] = (uint8_t)(code_lo >> 8);
    }

    bit_buffer_reset(instance->tx_buffer);
    bit_buffer_append_bytes(instance->tx_buffer, resp_buf, resp_size);
    free(resp_buf);

    return felica_listener_frame_exchange(instance, instance->tx_buffer);
}

static FelicaError felica_listener_command_handler_request_system_code(
    FelicaListener* instance,
    const FelicaListenerGenericRequest* const generic_request) {
    UNUSED(generic_request);
    FURI_LOG_D(TAG, "Request System Code cmd");

    uint32_t system_count = simple_array_get_count(instance->data->systems);
    size_t resp_size = sizeof(FelicaCommandHeaderRaw) + 1 + system_count * 2;

    uint8_t* resp_buf = malloc(resp_size);
    FelicaListSystemCodeCommandResponse* resp = (FelicaListSystemCodeCommandResponse*)resp_buf;

    resp->header.length = (uint8_t)resp_size;
    resp->header.command = FELICA_CMD_REQUEST_SYSTEM_CODE_RESP;
    resp->header.idm = felica_listener_get_current_idm(instance);
    resp->system_count = (uint8_t)system_count;

    for(uint32_t i = 0; i < system_count; i++) {
        const FelicaSystem* system = simple_array_cget(instance->data->systems, i);
        resp->system_code[i * 2] = (system->system_code >> 8) & 0xFF;
        resp->system_code[i * 2 + 1] = system->system_code & 0xFF;
    }

    bit_buffer_reset(instance->tx_buffer);
    bit_buffer_append_bytes(instance->tx_buffer, resp_buf, resp_size);
    free(resp_buf);

    return felica_listener_frame_exchange(instance, instance->tx_buffer);
}

// ---------------------------------------------------------------------------
// FeliCa Standard DES mutual-authentication helpers
// ---------------------------------------------------------------------------

#define FELICA_STANDARD_COMMUNICATION_ID_SIZE          (6U)
#define FELICA_STANDARD_AUTH2_COMMUNICATION_ID_OFFSET  (8U - FELICA_STANDARD_COMMUNICATION_ID_SIZE)
#define FELICA_STANDARD_SECURE_COMMUNICATION_ID_OFFSET (8U - FELICA_STANDARD_COMMUNICATION_ID_SIZE)

// Compute single-DES CBC encrypt/decrypt (key=8B, IV=8B)
static void felica_std_des_cbc_encrypt(
    const uint8_t* key,
    const uint8_t* iv,
    const uint8_t* in,
    uint8_t* out,
    size_t len) {
    mbedtls_des_context ctx;
    mbedtls_des_init(&ctx);
    mbedtls_des_setkey_enc(&ctx, key);
    uint8_t iv_buf[8];
    memcpy(iv_buf, iv, 8);
    mbedtls_des_crypt_cbc(&ctx, MBEDTLS_DES_ENCRYPT, len, iv_buf, in, out);
    mbedtls_des_free(&ctx);
}

static void felica_std_des_cbc_decrypt(
    const uint8_t* key,
    const uint8_t* iv,
    const uint8_t* in,
    uint8_t* out,
    size_t len) {
    mbedtls_des_context ctx;
    mbedtls_des_init(&ctx);
    mbedtls_des_setkey_dec(&ctx, key);
    uint8_t iv_buf[8];
    memcpy(iv_buf, iv, 8);
    mbedtls_des_crypt_cbc(&ctx, MBEDTLS_DES_DECRYPT, len, iv_buf, in, out);
    mbedtls_des_free(&ctx);
}

typedef struct {
    uint8_t group_idm_xor[8];
    uint8_t pcd_key[8];
    uint8_t picc_key[8];
} FelicaStandardMutualAuthKeys;

static void felica_std_des2_ede_encrypt(
    const uint8_t* key1,
    const uint8_t* key2,
    const uint8_t* input,
    uint8_t* output) {
    uint8_t tmp1[8];
    uint8_t tmp2[8];
    felica_des_ecb_encrypt(key1, input, tmp1);
    felica_des_ecb_decrypt(key2, tmp1, tmp2);
    felica_des_ecb_encrypt(key1, tmp2, output);
}

static void felica_std_des2_ede_decrypt(
    const uint8_t* key1,
    const uint8_t* key2,
    const uint8_t* input,
    uint8_t* output) {
    uint8_t tmp1[8];
    uint8_t tmp2[8];
    felica_des_ecb_decrypt(key1, input, tmp1);
    felica_des_ecb_encrypt(key2, tmp1, tmp2);
    felica_des_ecb_decrypt(key1, tmp2, output);
}

static void felica_std_derive_mutual_auth_keys(
    const uint8_t* group_key,
    const uint8_t* user_key,
    const FelicaIDm* idm,
    FelicaStandardMutualAuthKeys* keys) {
    // Diagram notation:
    //   A = Kg XOR IDm
    //   B = DES_A(Ks)
    //   C = DES_B(A)
    // PCD cryptograms (1A/2B) use 2-key EDE (B, A), while PICC cryptograms
    // (1B/2A) use 2-key EDE (A, C).
    for(size_t i = 0; i < sizeof(keys->group_idm_xor); i++) {
        keys->group_idm_xor[i] = group_key[i] ^ idm->data[i];
    }
    felica_des_ecb_encrypt(keys->group_idm_xor, user_key, keys->pcd_key);
    felica_des_ecb_encrypt(keys->pcd_key, keys->group_idm_xor, keys->picc_key);
}

// MAC: acc = [len, cc, 0,0,0,0,0,0]; for each 8B block of data: acc = DES_enc(acc, block_as_key)
static void felica_std_compute_mac(
    uint8_t pkt_len,
    uint8_t cmd_code,
    const uint8_t* data,
    size_t data_len,
    uint8_t* mac_out) {
    uint8_t acc[8] = {pkt_len, cmd_code, 0, 0, 0, 0, 0, 0};
    for(size_t i = 0; i + 8 <= data_len; i += 8) {
        uint8_t tmp[8];
        felica_des_ecb_encrypt(data + i, acc, tmp);
        memcpy(acc, tmp, 8);
    }
    memcpy(mac_out, acc, 8);
}

// Apply PKCS#5 padding (PICC→PCD): add (8 - len%8) bytes each equal to that count
static size_t felica_std_pkcs5_pad(const uint8_t* in, size_t len, uint8_t* out) {
    uint8_t pad = (uint8_t)(8 - (len % 8));
    memcpy(out, in, len);
    memset(out + len, pad, pad);
    return len + pad;
}

// ---------------------------------------------------------------------------
// Authentication 1 handler (command 0x10)
// Request:  Length + 0x10 + [IDm(8)] + n(1) + AreaCodes(2n) + o(1) +
//           SvcCodes(2o) + 1A(8)
// Response: Length + 0x11 + [IDm(8)] + 1B(8) + 2A(8)
// ---------------------------------------------------------------------------
static FelicaError felica_listener_command_handler_auth1(
    FelicaListener* instance,
    const FelicaListenerGenericRequest* const generic_request) {
    const uint8_t* raw = (const uint8_t*)generic_request;
    const size_t packet_len = raw[0];
    felica_listener_log_hex("Auth1 rx", raw, packet_len);
    if(packet_len < 2 + 1 + 1 + 8) return FelicaErrorProtocol;

    const FelicaIDm current_idm = felica_listener_get_current_idm(instance);
    const bool has_idm = packet_len >= 10 &&
                         memcmp(raw + 2, current_idm.data, sizeof(current_idm.data)) == 0;
    size_t off = has_idm ? 10 : 2;

    if(off >= packet_len) return FelicaErrorProtocol;
    const uint8_t n = raw[off++];
    if(n > COUNT_OF(instance->auth_area_codes) || (size_t)n * 2 > packet_len - off)
        return FelicaErrorProtocol;
    uint16_t area_codes[16];
    for(uint8_t i = 0; i < n; i++) {
        area_codes[i] = (uint16_t)(raw[off] | ((uint16_t)raw[off + 1] << 8));
        off += 2;
    }

    if(off >= packet_len) return FelicaErrorProtocol;
    const uint8_t o = raw[off++];
    if(o > COUNT_OF(instance->auth_service_codes) || (size_t)o * 2 > packet_len - off)
        return FelicaErrorProtocol;
    uint16_t svc_codes[16];
    for(uint8_t i = 0; i < o; i++) {
        svc_codes[i] = (uint16_t)(raw[off] | ((uint16_t)raw[off + 1] << 8));
        off += 2;
    }

    if(packet_len - off != 8) return FelicaErrorProtocol;
    const uint8_t* challenge_1a = raw + off;

    const FelicaSystem* system = felica_listener_get_current_system(instance);
    if(!system) return FelicaErrorProtocol;

    // Derive group and user service keys
    uint8_t group_key[8];
    felica_des_derive_group_service_key(system, area_codes, n, group_key);
    uint8_t user_key[8];
    felica_des_derive_user_service_key(group_key, system, svc_codes, o, user_key);

    // Save session keys and service/area codes for later commands
    memcpy(instance->des_user_key, user_key, 8);
    memcpy(instance->des_group_key, group_key, 8);
    instance->auth_area_count = n;
    for(uint8_t i = 0; i < n; i++)
        instance->auth_area_codes[i] = area_codes[i];
    instance->auth_service_count = o;
    for(uint8_t i = 0; i < o; i++)
        instance->auth_service_codes[i] = svc_codes[i];
    instance->auth_system_idx = instance->current_system_idx;

    FelicaStandardMutualAuthKeys mutual_auth_keys;
    felica_std_derive_mutual_auth_keys(group_key, user_key, &current_idm, &mutual_auth_keys);

    // Decrypt 1A with 2-key EDE (B, A) to recover R1.
    felica_std_des2_ede_decrypt(
        mutual_auth_keys.pcd_key, mutual_auth_keys.group_idm_xor, challenge_1a, instance->r1);
    felica_listener_log_hex("Auth1 1A (raw)", challenge_1a, 8);
    felica_listener_log_hex("Auth1 R1 (decrypted)", instance->r1, 8);

    // Encrypt R1 with 2-key EDE (A, C) → 1B.
    uint8_t challenge_1b[8];
    felica_std_des2_ede_encrypt(
        mutual_auth_keys.group_idm_xor, mutual_auth_keys.picc_key, instance->r1, challenge_1b);

    // Generate R2 and encrypt it with the same PICC-side EDE keys → 2A.
    furi_hal_random_fill_buf(instance->r2, 8);
    felica_listener_log_hex("Auth1 R2 (generated)", instance->r2, 8);
    uint8_t challenge_2a[8];
    felica_std_des2_ede_encrypt(
        mutual_auth_keys.group_idm_xor, mutual_auth_keys.picc_key, instance->r2, challenge_2a);

    instance->des_auth_state = 1;

    // Mirror the request's optional IDm so both command variants remain interoperable.
    const size_t response_data_offset = has_idm ? 10 : 2;
    const size_t response_len = response_data_offset + 16;
    uint8_t resp[26];
    resp[0] = response_len;
    resp[1] = FELICA_CMD_AUTHENTICATION1_RESP;
    if(has_idm) memcpy(resp + 2, current_idm.data, sizeof(current_idm.data));
    memcpy(resp + response_data_offset, challenge_1b, 8);
    memcpy(resp + response_data_offset + 8, challenge_2a, 8);

    bit_buffer_reset(instance->tx_buffer);
    bit_buffer_append_bytes(instance->tx_buffer, resp, response_len);
    return felica_listener_frame_exchange(instance, instance->tx_buffer);
}

// ---------------------------------------------------------------------------
// Authentication 2 handler (command 0x12)
// Request:  Length + 0x12 + [IDm(8)] + 2B(8)
// Response: Length + 0x13 + Encrypt(counter(2)+R1[2:7](6)+IDi(8)+PMi(8)+MAC(8))
// ---------------------------------------------------------------------------
static FelicaError felica_listener_command_handler_auth2(
    FelicaListener* instance,
    const FelicaListenerGenericRequest* const generic_request) {
    if(instance->des_auth_state != 1) return FelicaErrorProtocol;

    const uint8_t* raw = (const uint8_t*)generic_request;
    const size_t packet_len = raw[0];
    felica_listener_log_hex("Auth2 rx", raw, packet_len);
    const FelicaIDm current_idm = felica_listener_get_current_idm(instance);
    size_t challenge_offset;
    if(packet_len == 10) {
        challenge_offset = 2;
    } else if(packet_len == 18 && memcmp(raw + 2, current_idm.data, sizeof(current_idm.data)) == 0) {
        challenge_offset = 10;
    } else {
        return FelicaErrorProtocol;
    }
    const uint8_t* challenge_2b = raw + challenge_offset;

    // Decrypt 2B with the same PCD-side EDE keys as 1A and verify R2.
    FelicaStandardMutualAuthKeys mutual_auth_keys;
    felica_std_derive_mutual_auth_keys(
        instance->des_group_key, instance->des_user_key, &current_idm, &mutual_auth_keys);
    uint8_t recv_r2[8];
    felica_std_des2_ede_decrypt(
        mutual_auth_keys.pcd_key, mutual_auth_keys.group_idm_xor, challenge_2b, recv_r2);
    felica_listener_log_hex("Auth2 2B (raw)", challenge_2b, 8);
    felica_listener_log_hex("Auth2 R2 (decrypted)", recv_r2, 8);
    felica_listener_log_hex("Auth2 R2 (expected)", instance->r2, 8);
    if(memcmp(recv_r2, instance->r2, 8) != 0) return FelicaErrorProtocol;

    instance->des_auth_state = 2;
    instance->des_comm_counter = 0;
    felica_listener_set_mode(instance, FELICA_LISTENER_MODE_AUTHENTICATED);
    FURI_LOG_D(TAG, "Mutual authentication complete: Mode 3");

    // Response: Length(1) + 0x13(1) +
    // Encrypt(counter(2)+communication ID R1[2:7](6)+IDi(8)+PMi(8)+MAC(8)) = 34 bytes
    // No IDm in Auth2 response (differs from standard FeliCa commands)
    const uint8_t total_len = 34; // 0x22
    const FelicaSystem* auth_system =
        simple_array_cget(instance->data->systems, instance->auth_system_idx);

    // Authentication 2 uses the last six bytes of R1 as its communication identifier,
    // same as the rest of the secure communication commands.
    // Build plaintext: counter(2) + communication ID(6) + IDi(8) + PMi(8) = 24 bytes
    uint8_t plain[24];
    plain[0] = 0; // counter low
    plain[1] = 0; // counter high
    memcpy(
        plain + 2,
        instance->r1 + FELICA_STANDARD_AUTH2_COMMUNICATION_ID_OFFSET,
        FELICA_STANDARD_COMMUNICATION_ID_SIZE);
    memcpy(plain + 8, auth_system->idi, 8);
    memcpy(plain + 16, auth_system->pmi, 8);

    // Compute MAC over plain[0..23] (3 blocks), seed = [total_len, 0x13, 0,0,0,0,0,0]
    uint8_t mac[8];
    felica_std_compute_mac(total_len, FELICA_CMD_AUTHENTICATION2_RESP, plain, 24, mac);

    // Full plaintext = plain(24) + mac(8) = 32 bytes (4 DES blocks, no padding needed)
    uint8_t full_plain[32];
    memcpy(full_plain, plain, 24);
    memcpy(full_plain + 24, mac, 8);

    // Encrypt with R2 (CBC, IV=0)
    uint8_t iv[8] = {0};
    uint8_t encrypted[32];
    felica_std_des_cbc_encrypt(instance->r2, iv, full_plain, encrypted, 32);

    uint8_t resp[34];
    resp[0] = total_len;
    resp[1] = FELICA_CMD_AUTHENTICATION2_RESP;
    memcpy(resp + 2, encrypted, 32);

    bit_buffer_reset(instance->tx_buffer);
    bit_buffer_append_bytes(instance->tx_buffer, resp, 34);
    return felica_listener_frame_exchange(instance, instance->tx_buffer);
}

// Max blocks per secure Read/Write, bounded by what a single encrypted response
// or request frame can hold in the 256-byte listener buffer (incl. 2-byte CRC).
//   Read response = 2 + PKCS#5(2+6+1+1+1 + 16N) + 8(MAC) + 2(CRC); N=14 -> 252B.
//   Write request  = 2 + PKCS#5(2+6+1 + 2N + 16N) + 8(MAC) + 2(CRC); N=8 -> 172B.
// Fifteen secure-read blocks would require 268 bytes after mandatory PKCS#5
// padding, so fourteen is the largest representable response.
#define FELICA_STANDARD_SECURE_READ_BLOCK_MAX  (14U)
#define FELICA_STANDARD_SECURE_WRITE_BLOCK_MAX (8U)

typedef struct {
    uint8_t service_index;
    uint16_t block_number;
} FelicaStandardSecureBlockListElement;

static bool felica_std_parse_secure_block_list(
    const uint8_t* data,
    size_t data_len,
    uint8_t block_count,
    FelicaStandardSecureBlockListElement* elements,
    size_t elements_count,
    size_t* bytes_consumed) {
    if((block_count == 0) || (block_count > elements_count)) return false;

    size_t offset = 0;
    for(uint8_t i = 0; i < block_count; i++) {
        if(data_len - offset < 2) return false;

        const bool is_two_byte = (data[offset] & 0x80U) != 0;
        const size_t element_size = is_two_byte ? 2U : 3U;
        if(data_len - offset < element_size) return false;

        elements[i].service_index = data[offset] & 0x0FU;
        elements[i].block_number = data[offset + 1];
        if(!is_two_byte) {
            elements[i].block_number |= (uint16_t)data[offset + 2] << 8;
        }
        offset += element_size;
    }

    *bytes_consumed = offset;
    return true;
}

// Readers in the field use both PKCS#5 and zero padding for secure requests.
// Accept either representation; the padding remains authenticated because it is
// included in the MAC that is verified before this function is called.
static bool
    felica_std_check_request_padding(const uint8_t* data, size_t data_len, size_t unpadded_len) {
    if(unpadded_len > data_len) return false;

    const size_t pad_len = data_len - unpadded_len;
    if(pad_len == 0) return true;
    if(pad_len > 8) return false;

    bool pkcs5_padding = true;
    bool zero_padding = true;
    for(size_t i = unpadded_len; i < data_len; i++) {
        if(data[i] != pad_len) pkcs5_padding = false;
        if(data[i] != 0) zero_padding = false;
    }
    return pkcs5_padding || zero_padding;
}

static bool felica_std_check_secure_communication_id(
    const FelicaListener* instance,
    const uint8_t* communication_id) {
    return memcmp(
               communication_id,
               instance->r1 + FELICA_STANDARD_SECURE_COMMUNICATION_ID_OFFSET,
               FELICA_STANDARD_COMMUNICATION_ID_SIZE) == 0;
}

static bool
    felica_std_check_command_counter(const FelicaListener* instance, uint16_t command_counter) {
    // Accept any counter that moved forward: readers are allowed to skip values, so
    // only a repeated or older counter is treated as a replay. One value is kept
    // available for the response counter, so a new authentication is required once
    // the two-byte counter is exhausted.
    return command_counter > instance->des_comm_counter && command_counter < UINT16_MAX;
}

// ---------------------------------------------------------------------------
// Secure Read handler (command 0x14)
// Request:  Length + 0x14 + Encrypt(pad(counter(2)+communication_id(6)+
//           blk_cnt(1)+blk_list)+MAC(8))
// Response: Length + 0x15 + Encrypt(pkcs5_pad(counter+1(2)+communication_id(6)+
//           SF1(1)+SF2(1)+blk_cnt(1)+blk_data)+MAC(8))
// No IDm in either direction. Service code index refers to Auth1 service codes.
// ---------------------------------------------------------------------------
static FelicaError felica_listener_command_handler_secure_read(
    FelicaListener* instance,
    const FelicaListenerGenericRequest* const generic_request) {
    if(instance->des_auth_state != 2) return FelicaErrorProtocol;

    const uint8_t* raw = (const uint8_t*)generic_request;
    uint8_t pkt_len = raw[0];
    // Encrypted payload starts at offset 2 (Length + 0x14 only, no IDm)
    if(pkt_len < 2) return FelicaErrorProtocol;
    size_t enc_len = (size_t)(pkt_len - 2);
    if(enc_len == 0 || enc_len % 8 != 0) return FelicaErrorProtocol;

    const uint8_t* enc_payload = raw + 2;
    uint8_t decrypted[64];
    if(enc_len > sizeof(decrypted)) return FelicaErrorProtocol;
    uint8_t iv[8] = {0};
    felica_std_des_cbc_decrypt(instance->r2, iv, enc_payload, decrypted, enc_len);

    // Minimum: counter(2)+communication ID(6)+blk_cnt(1)+block list(2)+padding+MAC(8)
    // occupies at least three DES blocks.
    if(enc_len < 24) return FelicaErrorProtocol;
    felica_listener_log_hex("Read decrypted", decrypted, enc_len);
    uint16_t counter = (uint16_t)(decrypted[0] | ((uint16_t)decrypted[1] << 8));
    if(!felica_std_check_command_counter(instance, counter)) {
        FURI_LOG_E(
            TAG,
            "Read counter not advancing: got %u, must be greater than %u",
            counter,
            instance->des_comm_counter);
        return FelicaErrorProtocol;
    }
    if(!felica_std_check_secure_communication_id(instance, decrypted + 2)) {
        felica_listener_log_hex(
            "Read comm_id (got)", decrypted + 2, FELICA_STANDARD_COMMUNICATION_ID_SIZE);
        felica_listener_log_hex(
            "Read comm_id (expected, R1[2:7])",
            instance->r1 + FELICA_STANDARD_SECURE_COMMUNICATION_ID_OFFSET,
            FELICA_STANDARD_COMMUNICATION_ID_SIZE);
        return FelicaErrorProtocol;
    }

    // MAC covers all bytes except last 8 (padding is included in MAC-covered data)
    uint8_t expected_mac[8];
    size_t mac_data_len = enc_len - 8;
    felica_std_compute_mac(pkt_len, FELICA_CMD_READ, decrypted, mac_data_len, expected_mac);
    if(memcmp(expected_mac, decrypted + mac_data_len, 8) != 0) {
        felica_listener_log_hex("Read MAC (got)", decrypted + mac_data_len, 8);
        felica_listener_log_hex("Read MAC (expected)", expected_mac, 8);
        return FelicaErrorProtocol;
    }

    // Parse block list after counter(2) + communication ID(6) + block count(1).
    const size_t block_count_offset = 2 + FELICA_STANDARD_COMMUNICATION_ID_SIZE;
    const uint8_t blk_cnt = decrypted[block_count_offset];
    FelicaStandardSecureBlockListElement block_list[FELICA_STANDARD_SECURE_READ_BLOCK_MAX];
    size_t block_list_size = 0;
    if(!felica_std_parse_secure_block_list(
           decrypted + block_count_offset + 1,
           mac_data_len - (block_count_offset + 1),
           blk_cnt,
           block_list,
           COUNT_OF(block_list),
           &block_list_size)) {
        return FelicaErrorProtocol;
    }

    const size_t unpadded_len = block_count_offset + 1 + block_list_size;
    if(!felica_std_check_request_padding(decrypted, mac_data_len, unpadded_len))
        return FelicaErrorProtocol;

    const FelicaSystem* system = NULL;
    if(instance->auth_system_idx < simple_array_get_count(instance->data->systems)) {
        system = simple_array_cget(instance->data->systems, instance->auth_system_idx);
    }

    uint8_t sf1 = 0, sf2 = 0;
    uint8_t block_data[FELICA_STANDARD_SECURE_READ_BLOCK_MAX][FELICA_DATA_BLOCK_SIZE];
    uint8_t actual_cnt = 0;

    for(uint8_t i = 0; i < blk_cnt; i++) {
        const uint8_t svc_idx = block_list[i].service_index;
        const uint16_t blk_num = block_list[i].block_number;
        if(svc_idx >= instance->auth_service_count || !system) {
            sf1 = 0xFF;
            sf2 = 0xA8;
            break;
        }
        uint16_t svc_code = instance->auth_service_codes[svc_idx];
        const FelicaPublicBlock* pb = felica_std_find_public_block(system, svc_code, blk_num);
        bool found = pb != NULL;
        if(found) {
            memcpy(block_data[actual_cnt], pb->block.data, FELICA_DATA_BLOCK_SIZE);
        }
        if(!found) {
            FURI_LOG_E(
                TAG,
                "Secure Read block missing: system=%u service=%04X block=%04X loaded=%lu",
                instance->auth_system_idx,
                svc_code,
                blk_num,
                simple_array_get_count(system->public_blocks));
            const uint32_t public_block_count = simple_array_get_count(system->public_blocks);
            for(uint32_t j = 0; j < public_block_count; j++) {
                const FelicaPublicBlock* candidate = simple_array_cget(system->public_blocks, j);
                if((candidate->service_code >> 6) == (svc_code >> 6) &&
                   candidate->block_idx + 1 >= blk_num && candidate->block_idx <= blk_num + 1) {
                    FURI_LOG_E(
                        TAG,
                        "Secure Read candidate: entry=%lu service=%04X block=%02X",
                        j,
                        candidate->service_code,
                        candidate->block_idx);
                }
            }
            sf1 = 0xFF;
            sf2 = 0xA8;
            break;
        }
        actual_cnt++;
    }

    // Build response plaintext: counter+1(2)+communication ID(6)+SF1(1)+SF2(1)+
    // block count(1)+block data. The block count is present even for an error response.
    uint16_t resp_counter = counter + 1;
    // Remember the counter the reader actually sent: the next request only has to be
    // greater than it. Readers disagree on whether the response counter consumes a
    // value, so this accepts both counter+1 and counter+2 as the next request.
    instance->des_comm_counter = counter;
    uint8_t resp_plain
        [2 + FELICA_STANDARD_COMMUNICATION_ID_SIZE + 1 + 1 + 1 +
         FELICA_STANDARD_SECURE_READ_BLOCK_MAX * FELICA_DATA_BLOCK_SIZE];
    size_t resp_plain_len = 0;
    resp_plain[resp_plain_len++] = (uint8_t)(resp_counter & 0xFF);
    resp_plain[resp_plain_len++] = (uint8_t)(resp_counter >> 8);
    memcpy(
        resp_plain + resp_plain_len,
        instance->r1 + FELICA_STANDARD_SECURE_COMMUNICATION_ID_OFFSET,
        FELICA_STANDARD_COMMUNICATION_ID_SIZE);
    resp_plain_len += FELICA_STANDARD_COMMUNICATION_ID_SIZE;
    resp_plain[resp_plain_len++] = sf1;
    resp_plain[resp_plain_len++] = sf2;
    resp_plain[resp_plain_len++] = (sf1 == 0) ? actual_cnt : 0;
    if(sf1 == 0) {
        for(uint8_t i = 0; i < actual_cnt; i++) {
            memcpy(resp_plain + resp_plain_len, block_data[i], FELICA_DATA_BLOCK_SIZE);
            resp_plain_len += FELICA_DATA_BLOCK_SIZE;
        }
    }

    // PKCS#5 pad data, compute MAC over padded data, append MAC
    uint8_t padded_data[sizeof(resp_plain) + 8];
    size_t padded_data_len = felica_std_pkcs5_pad(resp_plain, resp_plain_len, padded_data);
    // final_pkt_len = 1(len)+1(code)+padded_data_len+8(MAC)  [no IDm]
    uint8_t final_pkt_len = (uint8_t)(1 + 1 + padded_data_len + 8);
    uint8_t resp_mac[8];
    felica_std_compute_mac(
        final_pkt_len, FELICA_CMD_READ_RESP, padded_data, padded_data_len, resp_mac);

    uint8_t full[sizeof(padded_data) + 8];
    memcpy(full, padded_data, padded_data_len);
    memcpy(full + padded_data_len, resp_mac, 8);
    size_t full_len = padded_data_len + 8;
    uint8_t enc_resp[sizeof(full)];
    memset(iv, 0, 8);
    felica_std_des_cbc_encrypt(instance->r2, iv, full, enc_resp, full_len);

    uint8_t resp_buf[2 + sizeof(enc_resp)];
    resp_buf[0] = final_pkt_len;
    resp_buf[1] = FELICA_CMD_READ_RESP;
    memcpy(resp_buf + 2, enc_resp, full_len);

    bit_buffer_reset(instance->tx_buffer);
    bit_buffer_append_bytes(instance->tx_buffer, resp_buf, final_pkt_len);
    return felica_listener_frame_exchange(instance, instance->tx_buffer);
}

// ---------------------------------------------------------------------------
// Secure Write handler (command 0x16)
// Request:  Length + 0x16 + Encrypt(pad(counter(2)+communication_id(6)+
//           blk_cnt(1)+blk_list+blk_data(16n))+MAC(8))
// Response: Length + 0x17 + Encrypt(pkcs5_pad(counter+1(2)+communication_id(6)+
//           SF1(1)+SF2(1))+MAC(8))
// No IDm in either direction. Service code index refers to Auth1 service codes.
// ---------------------------------------------------------------------------
static FelicaError felica_listener_command_handler_secure_write(
    FelicaListener* instance,
    const FelicaListenerGenericRequest* const generic_request) {
    if(instance->des_auth_state != 2) return FelicaErrorProtocol;

    const uint8_t* raw = (const uint8_t*)generic_request;
    uint8_t pkt_len = raw[0];
    if(pkt_len < 2) return FelicaErrorProtocol;
    size_t enc_len = (size_t)(pkt_len - 2);
    if(enc_len == 0 || enc_len % 8 != 0) return FelicaErrorProtocol;

    const uint8_t* enc_payload = raw + 2;
    uint8_t decrypted[192];
    if(enc_len > sizeof(decrypted)) return FelicaErrorProtocol;
    uint8_t iv[8] = {0};
    felica_std_des_cbc_decrypt(instance->r2, iv, enc_payload, decrypted, enc_len);

    if(enc_len < 24) return FelicaErrorProtocol;
    uint16_t counter = (uint16_t)(decrypted[0] | ((uint16_t)decrypted[1] << 8));
    if(!felica_std_check_command_counter(instance, counter)) return FelicaErrorProtocol;
    if(!felica_std_check_secure_communication_id(instance, decrypted + 2))
        return FelicaErrorProtocol;

    // MAC covers all bytes except last 8
    uint8_t expected_mac[8];
    size_t mac_data_len = enc_len - 8;
    felica_std_compute_mac(pkt_len, FELICA_CMD_WRITE, decrypted, mac_data_len, expected_mac);
    if(memcmp(expected_mac, decrypted + mac_data_len, 8) != 0) return FelicaErrorProtocol;

    // Parse block list after counter(2) + communication ID(6) + block count(1).
    const size_t block_count_offset = 2 + FELICA_STANDARD_COMMUNICATION_ID_SIZE;
    const uint8_t blk_cnt = decrypted[block_count_offset];
    FelicaStandardSecureBlockListElement block_list[FELICA_STANDARD_SECURE_WRITE_BLOCK_MAX];
    size_t block_list_size = 0;
    if(!felica_std_parse_secure_block_list(
           decrypted + block_count_offset + 1,
           mac_data_len - (block_count_offset + 1),
           blk_cnt,
           block_list,
           COUNT_OF(block_list),
           &block_list_size)) {
        return FelicaErrorProtocol;
    }

    const size_t block_data_offset = block_count_offset + 1 + block_list_size;
    const size_t block_data_size = (size_t)blk_cnt * FELICA_DATA_BLOCK_SIZE;
    if((block_data_offset > mac_data_len) ||
       (block_data_size > mac_data_len - block_data_offset)) {
        return FelicaErrorProtocol;
    }
    const size_t unpadded_len = block_data_offset + block_data_size;
    if(!felica_std_check_request_padding(decrypted, mac_data_len, unpadded_len))
        return FelicaErrorProtocol;

    struct {
        uint16_t svc_code;
        uint16_t blk_num;
        FelicaPublicBlock* block;
    } targets[FELICA_STANDARD_SECURE_WRITE_BLOCK_MAX];
    uint8_t valid_cnt = 0;
    uint8_t sf1 = 0, sf2 = 0;

    for(uint8_t i = 0; i < blk_cnt; i++) {
        const uint8_t svc_idx = block_list[i].service_index;
        if(svc_idx >= instance->auth_service_count) {
            sf1 = 0xFF;
            sf2 = 0xA8;
            break;
        }
        targets[valid_cnt].svc_code = instance->auth_service_codes[svc_idx];
        targets[valid_cnt].blk_num = block_list[i].block_number;
        targets[valid_cnt].block = NULL;
        valid_cnt++;
    }

    FelicaSystem* system = NULL;
    if(instance->auth_system_idx < simple_array_get_count(instance->data->systems)) {
        system = simple_array_get(instance->data->systems, instance->auth_system_idx);
    }
    if(sf1 == 0 && !system) {
        sf1 = 0xFF;
        sf2 = 0xA8;
    }

    // Validate every target before changing any block, so a failed multi-block write is atomic.
    if(sf1 == 0 && system) {
        for(uint8_t i = 0; i < valid_cnt; i++) {
            // Check service is writable
            bool svc_writable = false;
            uint32_t svc_count = simple_array_get_count(system->services);
            for(uint32_t k = 0; k < svc_count; k++) {
                const FelicaService* svc = simple_array_cget(system->services, k);
                if(svc->code == targets[i].svc_code) {
                    svc_writable = !(svc->attr & FELICA_SERVICE_ATTRIBUTE_READ_ONLY);
                    break;
                }
            }
            if(!svc_writable) {
                sf1 = 0xFF;
                sf2 = 0xA6;
                break;
            }
            FelicaPublicBlock* pb =
                felica_std_find_public_block_mut(system, targets[i].svc_code, targets[i].blk_num);
            bool found = pb != NULL;
            if(found) {
                targets[i].block = pb;
            }
            if(!found) {
                sf1 = 0xFF;
                sf2 = 0xA8;
                break;
            }
        }
    }

    if(sf1 == 0) {
        for(uint8_t i = 0; i < valid_cnt; i++) {
            memcpy(
                targets[i].block->block.data,
                decrypted + block_data_offset + i * FELICA_DATA_BLOCK_SIZE,
                FELICA_DATA_BLOCK_SIZE);
        }
    }

    // Build response: counter+1(2)+communication ID(6)+SF1(1)+SF2(1) = 10 bytes
    uint16_t resp_counter = counter + 1;
    // Remember the counter the reader actually sent: the next request only has to be
    // greater than it. Readers disagree on whether the response counter consumes a
    // value, so this accepts both counter+1 and counter+2 as the next request.
    instance->des_comm_counter = counter;
    uint8_t resp_plain[2 + FELICA_STANDARD_COMMUNICATION_ID_SIZE + 2];
    resp_plain[0] = (uint8_t)(resp_counter & 0xFF);
    resp_plain[1] = (uint8_t)(resp_counter >> 8);
    memcpy(
        resp_plain + 2,
        instance->r1 + FELICA_STANDARD_SECURE_COMMUNICATION_ID_OFFSET,
        FELICA_STANDARD_COMMUNICATION_ID_SIZE);
    resp_plain[8] = sf1;
    resp_plain[9] = sf2;

    // PKCS#5 pad the response data, compute its MAC, append the MAC, then encrypt all of it.
    uint8_t padded_data[16 + 8];
    size_t padded_data_len = felica_std_pkcs5_pad(resp_plain, sizeof(resp_plain), padded_data);
    // final_pkt_len = 1(len)+1(code)+padded_data_len+8(MAC)  [no IDm]
    uint8_t final_pkt_len = (uint8_t)(1 + 1 + padded_data_len + 8);
    uint8_t resp_mac[8];
    felica_std_compute_mac(
        final_pkt_len, FELICA_CMD_WRITE_RESP, padded_data, padded_data_len, resp_mac);

    uint8_t full[sizeof(padded_data) + 8];
    memcpy(full, padded_data, padded_data_len);
    memcpy(full + padded_data_len, resp_mac, 8);
    size_t full_len = padded_data_len + 8;
    uint8_t enc_resp[sizeof(full)];
    memset(iv, 0, 8);
    felica_std_des_cbc_encrypt(instance->r2, iv, full, enc_resp, full_len);

    uint8_t resp_buf[64];
    resp_buf[0] = final_pkt_len;
    resp_buf[1] = FELICA_CMD_WRITE_RESP;
    memcpy(resp_buf + 2, enc_resp, full_len);

    bit_buffer_reset(instance->tx_buffer);
    bit_buffer_append_bytes(instance->tx_buffer, resp_buf, final_pkt_len);
    return felica_listener_frame_exchange(instance, instance->tx_buffer);
}

static FelicaError felica_listener_process_request(
    FelicaListener* instance,
    const FelicaListenerGenericRequest* generic_request) {
    const uint8_t cmd_code = generic_request->header.code;
    switch(cmd_code) {
    case FELICA_CMD_REQUEST_RESPONSE:
        return felica_listener_command_handler_request_response(instance, generic_request);
    case FELICA_CMD_REQUEST_SERVICE:
        return felica_listener_command_handler_request_service(instance, generic_request);
    case FELICA_CMD_READ_WITHOUT_ENCRYPTION:
        if(instance->data->workflow_type == FelicaStandard) {
            return felica_listener_command_handler_standard_read(instance, generic_request);
        }
        return felica_listener_command_handler_read(instance, generic_request);
    case FELICA_CMD_WRITE_WITHOUT_ENCRYPTION:
        if(instance->data->workflow_type == FelicaStandard) {
            return felica_listener_command_handler_standard_write(instance, generic_request);
        }
        return felica_listener_command_handler_write(instance, generic_request);
    case FELICA_CMD_LIST_SERVICE_CODE:
        return felica_listener_command_handler_search_service_code(instance, generic_request);
    case FELICA_CMD_REQUEST_SYSTEM_CODE:
        return felica_listener_command_handler_request_system_code(instance, generic_request);
    case FELICA_CMD_AUTHENTICATION1:
        if(instance->data->workflow_type == FelicaStandard) {
            return felica_listener_command_handler_auth1(instance, generic_request);
        }
        return FelicaErrorNotPresent;
    case FELICA_CMD_AUTHENTICATION2:
        if(instance->data->workflow_type == FelicaStandard) {
            return felica_listener_command_handler_auth2(instance, generic_request);
        }
        return FelicaErrorNotPresent;
    case FELICA_CMD_READ:
        if(instance->data->workflow_type == FelicaStandard) {
            return felica_listener_command_handler_secure_read(instance, generic_request);
        }
        return FelicaErrorNotPresent;
    case FELICA_CMD_WRITE:
        if(instance->data->workflow_type == FelicaStandard) {
            return felica_listener_command_handler_secure_write(instance, generic_request);
        }
        return FelicaErrorNotPresent;
    default:
        FURI_LOG_E(TAG, "FeliCa incorrect command");
        return FelicaErrorNotPresent;
    }
}

static void felica_listener_populate_polling_response_header(
    FelicaListener* instance,
    FelicaListenerPollingResponseHeader* resp) {
    resp->idm = felica_listener_get_current_idm(instance);
    resp->pmm = instance->data->pmm;
    resp->response_code = FELICA_LISTENER_RESPONSE_POLLING;
}

static bool felica_listener_check_system_code(
    const FelicaListenerGenericRequest* const generic_request,
    uint16_t code) {
    return (
        generic_request->polling.system_code == code ||
        generic_request->polling.system_code == (code | 0x00FFU) ||
        generic_request->polling.system_code == (code | 0xFF00U));
}

static bool felica_listener_polling_targets_current_system(
    const FelicaListener* instance,
    const FelicaListenerGenericRequest* generic_request) {
    // The wildcard Polling includes the currently selected System, so it must not
    // terminate Mode 3 or produce another response during the authenticated session.
    if(generic_request->polling.system_code == FELICA_SYSTEM_CODE_CODE) return true;

    const FelicaSystem* current_system = felica_listener_get_current_system(instance);
    if(!current_system) return false;

    const uint16_t current_wire_code = __builtin_bswap16(current_system->system_code);
    return felica_listener_check_system_code(generic_request, current_wire_code);
}

// Returns the matched System's wire-format code, or FELICA_SYSTEM_CODE_CODE if none
// matched. When the match is a real entry in instance->data->systems (as opposed to
// the virtual NDEF/Lite-S codes), *matched_idx is set to its index so the caller can
// derive that System's IDm; otherwise *matched_idx is left at 0.
static uint16_t felica_listener_get_response_system_code(
    FelicaListener* instance,
    const FelicaListenerGenericRequest* const generic_request,
    uint8_t* matched_idx) {
    uint16_t resp_system_code = FELICA_SYSTEM_CODE_CODE;
    *matched_idx = 0;
    if(felica_listener_check_system_code(generic_request, FELICA_LISTENER_SYSTEM_CODE_NDEF) &&
       instance->data->data.fs.mc.data[FELICA_MC_SYS_OP] == 1) {
        // NDEF
        resp_system_code = FELICA_LISTENER_SYSTEM_CODE_NDEF;
    } else if(felica_listener_check_system_code(
                  generic_request, FELICA_LISTENER_SYSTEM_CODE_LITES)) {
        // Lite-S
        resp_system_code = FELICA_LISTENER_SYSTEM_CODE_LITES;
    } else {
        uint32_t system_count = simple_array_get_count(instance->data->systems);
        for(uint32_t i = 0; i < system_count; i++) {
            const FelicaSystem* system = simple_array_cget(instance->data->systems, i);
            uint16_t wire_code = __builtin_bswap16(system->system_code);
            if(felica_listener_check_system_code(generic_request, wire_code)) {
                resp_system_code = wire_code;
                *matched_idx = (uint8_t)i;
                break;
            }
        }
    }
    return resp_system_code;
}

static FelicaError felica_listener_process_system_code(
    FelicaListener* instance,
    const FelicaListenerGenericRequest* const generic_request) {
    FelicaError result = FelicaErrorFeatureUnsupported;
    do {
        uint8_t matched_idx = 0;
        uint16_t resp_system_code =
            felica_listener_get_response_system_code(instance, generic_request, &matched_idx);
        if(resp_system_code == FELICA_SYSTEM_CODE_CODE) break;

        // Switch context to the newly selected System before building the response,
        // since the response IDm (and all subsequent commands) must reflect it.
        instance->current_system_idx = matched_idx;

        FelicaListenerPollingResponse* resp = malloc(sizeof(FelicaListenerPollingResponse));
        felica_listener_populate_polling_response_header(instance, &resp->header);

        resp->header.length = sizeof(FelicaListenerPollingResponse);
        if(generic_request->polling.request_code == FELICA_LISTENER_REQUEST_SYSTEM_CODE) {
            resp->optional_request_data = resp_system_code;
        } else if(generic_request->polling.request_code == FELICA_LISTENER_REQUEST_PERFORMANCE) {
            resp->optional_request_data = FELICA_LISTENER_PERFORMANCE_VALUE;
        } else {
            resp->header.length = sizeof(FelicaListenerPollingResponseHeader);
        }

        bit_buffer_reset(instance->tx_buffer);
        bit_buffer_append_bytes(instance->tx_buffer, (uint8_t*)resp, resp->header.length);
        free(resp);

        result = felica_listener_frame_exchange(instance, instance->tx_buffer);
    } while(false);

    return result;
}

NfcCommand felica_listener_run(NfcGenericEvent event, void* context) {
    furi_assert(context);
    furi_assert(event.protocol == NfcProtocolInvalid);
    furi_assert(event.event_data);

    FelicaListener* instance = context;
    NfcEvent* nfc_event = event.event_data;
    NfcCommand command = NfcCommandContinue;

    if(nfc_event->type == NfcEventTypeFieldOn) {
        FURI_LOG_D(TAG, "Field On");
    } else if(nfc_event->type == NfcEventTypeListenerActivated) {
        instance->state = Felica_ListenerStateActivated;
        FURI_LOG_D(TAG, "Activated");
    } else if(nfc_event->type == NfcEventTypeFieldOff) {
        instance->state = Felica_ListenerStateIdle;
        FURI_LOG_D(TAG, "Field Off");
        felica_listener_reset(instance);
    } else if(nfc_event->type == NfcEventTypeRxEnd) {
        FURI_LOG_D(TAG, "Rx Done");
        do {
            if(!felica_crc_check(nfc_event->data.buffer)) {
                FURI_LOG_E(TAG, "Wrong CRC");
                break;
            }

            FelicaListenerGenericRequest* request =
                (FelicaListenerGenericRequest*)bit_buffer_get_data(nfc_event->data.buffer);

            uint8_t size = bit_buffer_get_size_bytes(nfc_event->data.buffer) - 2;
            if((request->length != size) ||
               (!felica_listener_check_block_list_size(instance, request))) {
                FURI_LOG_E(TAG, "Wrong request length");
                break;
            }

            if(request->header.code == FELICA_CMD_POLLING) {
                if(instance->mode == FELICA_LISTENER_MODE_AUTHENTICATED) {
                    if(felica_listener_polling_targets_current_system(instance, request)) {
                        FURI_LOG_D(TAG, "Current System Polling ignored in Mode 3");
                        // No response is transmitted in Mode 3, so explicitly restart
                        // reception for the command that follows this Polling frame.
                        command = NfcCommandReset;
                        break;
                    }

                    uint8_t target_system_idx = 0;
                    const uint16_t target_system_code = felica_listener_get_response_system_code(
                        instance, request, &target_system_idx);
                    if(target_system_code == FELICA_SYSTEM_CODE_CODE) {
                        FURI_LOG_D(TAG, "Unknown System Polling ignored in Mode 3");
                        command = NfcCommandReset;
                        break;
                    }

                    FURI_LOG_D(
                        TAG,
                        "Switching System by Polling: %u -> %u, Mode 0",
                        instance->current_system_idx,
                        target_system_idx);
                    felica_listener_set_mode(instance, FELICA_LISTENER_MODE_UNAUTHENTICATED);
                }

                // Will always respond at Time Slot 0 for now.
                nfc_felica_listener_timer_anticol_start(instance->nfc, 0);
                if(request->polling.system_code != FELICA_SYSTEM_CODE_CODE) {
                    FelicaError error = felica_listener_process_system_code(instance, request);
                    if(error == FelicaErrorFeatureUnsupported) {
                        command = NfcCommandReset;
                    } else if(error != FelicaErrorNone) {
                        FURI_LOG_E(
                            TAG, "Error when handling Polling with System Code: %2X", error);
                    }
                    break;
                } else {
                    FURI_LOG_E(TAG, "Hardware Polling command leaking through");
                    break;
                }
            } else if(
                request->header.code != FELICA_CMD_READ &&
                request->header.code != FELICA_CMD_WRITE &&
                request->header.code != FELICA_CMD_AUTHENTICATION1 &&
                request->header.code != FELICA_CMD_AUTHENTICATION2 &&
                !felica_listener_check_idm(instance, &request->header.idm)) {
                FURI_LOG_E(TAG, "Wrong IDm");
                break;
            }

            FelicaError error = felica_listener_process_request(instance, request);
            if(error != FelicaErrorNone) {
                FURI_LOG_E(TAG, "Processing error: %2X", error);
            }
        } while(false);
        bit_buffer_reset(nfc_event->data.buffer);
    }
    return command;
}

const NfcListenerBase nfc_listener_felica = {
    .alloc = (NfcListenerAlloc)felica_listener_alloc,
    .free = (NfcListenerFree)felica_listener_free,
    .set_callback = (NfcListenerSetCallback)felica_listener_set_callback,
    .get_data = (NfcListenerGetData)felica_listener_get_data,
    .run = (NfcListenerRun)felica_listener_run,
};
