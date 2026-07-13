#include "felica_listener_i.h"

#include "nfc/protocols/nfc_listener_base.h"
#include <nfc/helpers/felica_crc.h>
#include <furi_hal_nfc.h>
#include <furi_hal_random.h>

#define FELICA_LISTENER_MAX_BUFFER_SIZE     (128)
#define FELICA_LISTENER_CMD_POLLING         (0x00U)
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
    instance->mode = 0;
    instance->current_system_idx = 0;
    nfc_config(instance->nfc, NfcModeListener, NfcTechFelica);

    // PMm bytes 2-6 encode the max response time a reader should allow per command
    // (Request Service / Request Response / Read / Write / Auth). Cards saved from a
    // real (hardware-fast) FeliCa IC carry short values here; our software emulation
    // is slower to respond, so real readers following those short timeouts abandon
    // the session mid-transaction. Widen them to the max so readers wait long enough.
    memset(data->pmm.data + 2, 0xFF, FELICA_PMM_SIZE - 2);

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

// Max blocks for Standard read that fit within the 128-byte tx buffer (with CRC)
#define FELICA_STANDARD_READ_BLOCK_MAX (7U)

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

    uint8_t block_count = raw[11 + service_num * 2];
    if(block_count > FELICA_STANDARD_READ_BLOCK_MAX) {
        block_count = FELICA_STANDARD_READ_BLOCK_MAX;
    }
    const uint8_t* bptr = raw + 12 + service_num * 2;

    const FelicaSystem* system = felica_listener_get_current_system(instance);

    uint8_t sf1 = 0x00, sf2 = 0x00;
    uint8_t block_data[FELICA_STANDARD_READ_BLOCK_MAX][FELICA_DATA_BLOCK_SIZE];
    uint8_t actual_block_count = 0;

    for(uint8_t i = 0; i < block_count; i++) {
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
        bool found = false;
        uint32_t pb_count = simple_array_get_count(system->public_blocks);
        for(uint32_t j = 0; j < pb_count; j++) {
            const FelicaPublicBlock* pb = simple_array_cget(system->public_blocks, j);
            if(pb->service_code == svc_code && pb->block_idx == blk_num) {
                memcpy(block_data[actual_block_count], pb->block.data, FELICA_DATA_BLOCK_SIZE);
                found = true;
                break;
            }
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
                resp_buf + 13 + i * FELICA_DATA_BLOCK_SIZE,
                block_data[i],
                FELICA_DATA_BLOCK_SIZE);
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
            bool found = false;
            uint32_t pb_count = simple_array_get_count(system->public_blocks);
            for(uint32_t j = 0; j < pb_count; j++) {
                FelicaPublicBlock* pb = simple_array_get(system->public_blocks, j);
                if(pb->service_code == targets[i].svc_code && pb->block_idx == targets[i].blk_num) {
                    memcpy(
                        pb->block.data, bptr + i * FELICA_DATA_BLOCK_SIZE, FELICA_DATA_BLOCK_SIZE);
                    found = true;
                    break;
                }
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
// Request:  Length + 0x10 + IDm(8) + n(1) + AreaCodes(2n) + o(1) + SvcCodes(2o) + 1A(8)
// Response: Length + 0x11 + IDm(8) + 1B(8) + 2A(8)
// ---------------------------------------------------------------------------
static FelicaError felica_listener_command_handler_auth1(
    FelicaListener* instance,
    const FelicaListenerGenericRequest* const generic_request) {
    const uint8_t* raw = (const uint8_t*)generic_request;
    uint8_t off = 10; // past Length(1) + 0x10(1) + IDm(8)

    uint8_t n = raw[off++];
    if(n > 16) n = 16;
    uint16_t area_codes[16];
    for(uint8_t i = 0; i < n; i++) {
        area_codes[i] = (uint16_t)(raw[off] | ((uint16_t)raw[off + 1] << 8));
        off += 2;
    }

    uint8_t o = raw[off++];
    if(o > 16) o = 16;
    uint16_t svc_codes[16];
    for(uint8_t i = 0; i < o; i++) {
        svc_codes[i] = (uint16_t)(raw[off] | ((uint16_t)raw[off + 1] << 8));
        off += 2;
    }

    const uint8_t* challenge_1a = raw + off;

    const FelicaSystem* system = NULL;
    if(simple_array_get_count(instance->data->systems) > 0) {
        system = simple_array_cget(instance->data->systems, 0);
    }
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
    for(uint8_t i = 0; i < n; i++) instance->auth_area_codes[i] = area_codes[i];
    instance->auth_service_count = o;
    for(uint8_t i = 0; i < o; i++) instance->auth_service_codes[i] = svc_codes[i];
    instance->auth_system_idx = 0; // system 0 used (always index 0 for now)

    // Decrypt 1A with user key → R1
    felica_des_ecb_decrypt(user_key, challenge_1a, instance->r1);

    // Alternate key for 1B/2A = group_key XOR IDm
    uint8_t key_alt[8];
    for(int i = 0; i < 8; i++) key_alt[i] = group_key[i] ^ instance->data->idm.data[i];

    // Encrypt R1 → 1B
    uint8_t challenge_1b[8];
    felica_des_ecb_encrypt(key_alt, instance->r1, challenge_1b);

    // Generate R2 and encrypt → 2A
    furi_hal_random_fill_buf(instance->r2, 8);
    uint8_t challenge_2a[8];
    felica_des_ecb_encrypt(key_alt, instance->r2, challenge_2a);

    instance->des_auth_state = 1;

    // Build response: Length(1)+0x11(1)+IDm(8)+1B(8)+2A(8) = 26 bytes
    uint8_t resp[26];
    resp[0] = 26;
    resp[1] = FELICA_CMD_AUTHENTICATION1_RESP;
    memcpy(resp + 2, instance->data->idm.data, 8);
    memcpy(resp + 10, challenge_1b, 8);
    memcpy(resp + 18, challenge_2a, 8);

    bit_buffer_reset(instance->tx_buffer);
    bit_buffer_append_bytes(instance->tx_buffer, resp, 26);
    return felica_listener_frame_exchange(instance, instance->tx_buffer);
}

// ---------------------------------------------------------------------------
// Authentication 2 handler (command 0x12)
// Request:  Length + 0x12 + IDm(8) + 2B(8)
// Response: Length + 0x13 + IDm(8) + Encrypt(counter(2)+R1[0:5](6)+IDi(8)+PMi(8)+MAC(8))
// ---------------------------------------------------------------------------
static FelicaError felica_listener_command_handler_auth2(
    FelicaListener* instance,
    const FelicaListenerGenericRequest* const generic_request) {
    if(instance->des_auth_state != 1) return FelicaErrorProtocol;

    const uint8_t* raw = (const uint8_t*)generic_request;
    const uint8_t* challenge_2b = raw + 10; // past Length+0x12+IDm

    // Decrypt 2B with user key → verify equals R2
    uint8_t recv_r2[8];
    felica_des_ecb_decrypt(instance->des_user_key, challenge_2b, recv_r2);
    if(memcmp(recv_r2, instance->r2, 8) != 0) return FelicaErrorProtocol;

    instance->des_auth_state = 2;
    instance->des_comm_counter = 0;

    // Response: Length(1) + 0x13(1) + Encrypt(counter(2)+R1[0:5](6)+IDi(8)+PMi(8)+MAC(8)) = 34 bytes
    // No IDm in Auth2 response (differs from standard FeliCa commands)
    const uint8_t total_len = 34; // 0x22
    const FelicaSystem* auth_system =
        simple_array_cget(instance->data->systems, instance->auth_system_idx);

    // Build plaintext: counter(2) + R1[0:5](6) + IDi(8) + PMi(8) = 24 bytes
    uint8_t plain[24];
    plain[0] = 0; // counter low
    plain[1] = 0; // counter high
    memcpy(plain + 2, instance->r1, 6);
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

// Max blocks for encrypted read/write that fit within the tx buffer
#define FELICA_STANDARD_ENCRYPTED_READ_BLOCK_MAX (4U)

// ---------------------------------------------------------------------------
// Encrypted Read handler (command 0x30)
// Request:  Length + 0x30 + IDm(8) + Encrypt(null_pad(counter(2)+R1(8)+svc_num(1)+svcs(2n)+blk_cnt(1)+blk_list+MAC(8)))
// Response: Length + 0x31 + IDm(8) + Encrypt(pkcs5_pad(counter+1(2)+R1(8)+SF1(1)+SF2(1)+blk_cnt(1)+blk_data+MAC(8)))
// ---------------------------------------------------------------------------
static FelicaError felica_listener_command_handler_encrypted_read(
    FelicaListener* instance,
    const FelicaListenerGenericRequest* const generic_request) {
    if(instance->des_auth_state != 2) return FelicaErrorProtocol;

    const uint8_t* raw = (const uint8_t*)generic_request;
    uint8_t pkt_len = raw[0];
    // Encrypted payload starts at offset 10 (past Length+0x30+IDm)
    size_t enc_len = (size_t)(pkt_len - 10);
    if(enc_len == 0 || enc_len % 8 != 0) return FelicaErrorProtocol;

    const uint8_t* enc_payload = raw + 10;

    // Decrypt payload with R2 (CBC, IV=0)
    uint8_t decrypted[64]; // max reasonable size
    if(enc_len > sizeof(decrypted)) return FelicaErrorProtocol;
    uint8_t iv[8] = {0};
    felica_std_des_cbc_decrypt(instance->r2, iv, enc_payload, decrypted, enc_len);

    // Parse inner: counter(2) + R1(8) + svc_num(1) + svc_codes(2*svc_num) + blk_cnt(1) + blk_list + MAC(8)
    if(enc_len < 2 + 8 + 1 + 1 + 8) return FelicaErrorProtocol;
    uint16_t counter = (uint16_t)(decrypted[0] | ((uint16_t)decrypted[1] << 8));

    // Replay check
    if(counter <= instance->des_comm_counter) return FelicaErrorProtocol;
    // Verify R1
    if(memcmp(decrypted + 2, instance->r1, 8) != 0) return FelicaErrorProtocol;

    // Verify MAC: covers decrypted[0..enc_len-8-1], seed=[pkt_len, 0x30, 0...]
    uint8_t expected_mac[8];
    size_t mac_data_len = enc_len - 8; // exclude MAC at end
    felica_std_compute_mac(pkt_len, FELICA_CMD_READ_ENCRYPTED, decrypted, mac_data_len, expected_mac);
    if(memcmp(expected_mac, decrypted + mac_data_len, 8) != 0) return FelicaErrorProtocol;

    instance->des_comm_counter = counter;

    // Parse comm_data starting at offset 10
    uint8_t inner_off = 10;
    uint8_t svc_num = decrypted[inner_off++];
    uint16_t svc_codes[16];
    for(uint8_t i = 0; i < svc_num && i < 16; i++) {
        svc_codes[i] =
            (uint16_t)(decrypted[inner_off] | ((uint16_t)decrypted[inner_off + 1] << 8));
        inner_off += 2;
    }
    uint8_t blk_cnt = decrypted[inner_off++];
    if(blk_cnt > FELICA_STANDARD_ENCRYPTED_READ_BLOCK_MAX)
        blk_cnt = FELICA_STANDARD_ENCRYPTED_READ_BLOCK_MAX;

    const FelicaSystem* system = NULL;
    if(simple_array_get_count(instance->data->systems) > 0)
        system = simple_array_cget(instance->data->systems, 0);

    uint8_t sf1 = 0, sf2 = 0;
    uint8_t block_data[FELICA_STANDARD_ENCRYPTED_READ_BLOCK_MAX][FELICA_DATA_BLOCK_SIZE];
    uint8_t actual_cnt = 0;

    for(uint8_t i = 0; i < blk_cnt; i++) {
        uint8_t svc_idx = decrypted[inner_off] & 0x0F;
        bool is_2byte = (decrypted[inner_off] >> 7) != 0;
        uint8_t blk_num;
        if(is_2byte) {
            blk_num = decrypted[inner_off + 1];
            inner_off += 2;
        } else {
            blk_num = decrypted[inner_off + 1];
            inner_off += 3;
        }

        if(svc_idx >= svc_num || !system) {
            sf1 = 0xFF;
            sf2 = 0xA8;
            break;
        }
        uint16_t svc_code = svc_codes[svc_idx];
        bool found = false;
        uint32_t pb_count = simple_array_get_count(system->public_blocks);
        for(uint32_t j = 0; j < pb_count; j++) {
            const FelicaPublicBlock* pb = simple_array_cget(system->public_blocks, j);
            if(pb->service_code == svc_code && pb->block_idx == blk_num) {
                memcpy(block_data[actual_cnt], pb->block.data, FELICA_DATA_BLOCK_SIZE);
                found = true;
                break;
            }
        }
        if(!found) {
            sf1 = 0xFF;
            sf2 = 0xA8;
            break;
        }
        actual_cnt++;
    }

    // Build response inner plaintext: counter+1(2) + R1(8) + SF1(1)+SF2(1)+blk_cnt(1)+data
    uint16_t resp_counter = counter + 1;
    uint8_t resp_plain[2 + 8 + 1 + 1 + 1 + FELICA_STANDARD_ENCRYPTED_READ_BLOCK_MAX * FELICA_DATA_BLOCK_SIZE];
    size_t resp_plain_len = 0;
    resp_plain[resp_plain_len++] = (uint8_t)(resp_counter & 0xFF);
    resp_plain[resp_plain_len++] = (uint8_t)(resp_counter >> 8);
    memcpy(resp_plain + resp_plain_len, instance->r1, 8);
    resp_plain_len += 8;
    resp_plain[resp_plain_len++] = sf1;
    resp_plain[resp_plain_len++] = sf2;
    if(sf1 == 0) {
        resp_plain[resp_plain_len++] = actual_cnt;
        for(uint8_t i = 0; i < actual_cnt; i++) {
            memcpy(resp_plain + resp_plain_len, block_data[i], FELICA_DATA_BLOCK_SIZE);
            resp_plain_len += FELICA_DATA_BLOCK_SIZE;
        }
    }

    // PKCS#5 pad data first, compute MAC over padded data, append MAC at end
    uint8_t padded_data[sizeof(resp_plain) + 8];
    size_t padded_data_len = felica_std_pkcs5_pad(resp_plain, resp_plain_len, padded_data);
    // final_pkt_len = 1(len)+1(code)+8(IDm)+padded_data_len+8(MAC)
    uint8_t final_pkt_len = (uint8_t)(1 + 1 + 8 + padded_data_len + 8);
    uint8_t resp_mac[8];
    felica_std_compute_mac(
        final_pkt_len, FELICA_CMD_READ_ENCRYPTED_RESP, padded_data, padded_data_len, resp_mac);

    // Encrypt block = [padded_data][MAC]
    uint8_t full[sizeof(padded_data) + 8];
    memcpy(full, padded_data, padded_data_len);
    memcpy(full + padded_data_len, resp_mac, 8);
    size_t full_len = padded_data_len + 8;
    uint8_t enc_resp[sizeof(full)];
    memset(iv, 0, 8);
    felica_std_des_cbc_encrypt(instance->r2, iv, full, enc_resp, full_len);

    uint8_t resp_buf[128];
    resp_buf[0] = final_pkt_len;
    resp_buf[1] = FELICA_CMD_READ_ENCRYPTED_RESP;
    memcpy(resp_buf + 2, instance->data->idm.data, 8);
    memcpy(resp_buf + 10, enc_resp, full_len);

    bit_buffer_reset(instance->tx_buffer);
    bit_buffer_append_bytes(instance->tx_buffer, resp_buf, final_pkt_len);
    return felica_listener_frame_exchange(instance, instance->tx_buffer);
}

// ---------------------------------------------------------------------------
// Encrypted Write handler (command 0x32)
// Request:  Length + 0x32 + IDm(8) + Encrypt(null_pad(counter(2)+R1(8)+svc_num(1)+svcs(2n)+blk_cnt(1)+blk_list+blk_data+MAC(8)))
// Response: Length + 0x33 + IDm(8) + Encrypt(pkcs5_pad(counter+1(2)+R1(8)+SF1(1)+SF2(1)+MAC(8)))
// ---------------------------------------------------------------------------
static FelicaError felica_listener_command_handler_encrypted_write(
    FelicaListener* instance,
    const FelicaListenerGenericRequest* const generic_request) {
    if(instance->des_auth_state != 2) return FelicaErrorProtocol;

    const uint8_t* raw = (const uint8_t*)generic_request;
    uint8_t pkt_len = raw[0];
    size_t enc_len = (size_t)(pkt_len - 10);
    if(enc_len == 0 || enc_len % 8 != 0) return FelicaErrorProtocol;

    const uint8_t* enc_payload = raw + 10;
    uint8_t decrypted[128];
    if(enc_len > sizeof(decrypted)) return FelicaErrorProtocol;
    uint8_t iv[8] = {0};
    felica_std_des_cbc_decrypt(instance->r2, iv, enc_payload, decrypted, enc_len);

    if(enc_len < 2 + 8 + 1 + 1 + 8) return FelicaErrorProtocol;
    uint16_t counter = (uint16_t)(decrypted[0] | ((uint16_t)decrypted[1] << 8));
    if(counter <= instance->des_comm_counter) return FelicaErrorProtocol;
    if(memcmp(decrypted + 2, instance->r1, 8) != 0) return FelicaErrorProtocol;

    // Verify MAC
    uint8_t expected_mac[8];
    size_t mac_data_len = enc_len - 8;
    felica_std_compute_mac(
        pkt_len, FELICA_CMD_WRITE_ENCRYPTED, decrypted, mac_data_len, expected_mac);
    if(memcmp(expected_mac, decrypted + mac_data_len, 8) != 0) return FelicaErrorProtocol;

    instance->des_comm_counter = counter;

    uint8_t inner_off = 10;
    uint8_t svc_num = decrypted[inner_off++];
    uint16_t svc_codes[16];
    for(uint8_t i = 0; i < svc_num && i < 16; i++) {
        svc_codes[i] =
            (uint16_t)(decrypted[inner_off] | ((uint16_t)decrypted[inner_off + 1] << 8));
        inner_off += 2;
    }
    uint8_t blk_cnt = decrypted[inner_off++];
    if(blk_cnt > 8) blk_cnt = 8;

    struct {
        uint16_t svc_code;
        uint8_t blk_num;
    } targets[8];
    uint8_t valid_cnt = 0;
    uint8_t sf1 = 0, sf2 = 0;

    const FelicaSystem* system = NULL;
    if(simple_array_get_count(instance->data->systems) > 0)
        system = simple_array_cget(instance->data->systems, 0);

    for(uint8_t i = 0; i < blk_cnt && i < 8; i++) {
        uint8_t svc_idx = decrypted[inner_off] & 0x0F;
        bool is_2byte = (decrypted[inner_off] >> 7) != 0;
        uint8_t blk_num;
        if(is_2byte) {
            blk_num = decrypted[inner_off + 1];
            inner_off += 2;
        } else {
            blk_num = decrypted[inner_off + 1];
            inner_off += 3;
        }

        if(svc_idx >= svc_num || !system) {
            sf1 = 0xFF;
            sf2 = 0xA8;
            break;
        }
        uint16_t svc_code = svc_codes[svc_idx];

        // Check service is writable
        bool svc_found = false;
        uint32_t svc_count = simple_array_get_count(system->services);
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
        valid_cnt++;
    }

    // Block data follows the block list in the decrypted payload
    if(sf1 == 0 && system) {
        for(uint8_t i = 0; i < valid_cnt; i++) {
            bool found = false;
            uint32_t pb_count = simple_array_get_count(system->public_blocks);
            for(uint32_t j = 0; j < pb_count; j++) {
                FelicaPublicBlock* pb = simple_array_get(system->public_blocks, j);
                if(pb->service_code == targets[i].svc_code &&
                   pb->block_idx == targets[i].blk_num) {
                    memcpy(
                        pb->block.data,
                        decrypted + inner_off + i * FELICA_DATA_BLOCK_SIZE,
                        FELICA_DATA_BLOCK_SIZE);
                    found = true;
                    break;
                }
            }
            if(!found) {
                sf1 = 0xFF;
                sf2 = 0xA8;
                break;
            }
        }
    }

    // Build response inner: counter+1(2) + R1(8) + SF1(1) + SF2(1) = 12 bytes
    uint16_t resp_counter = counter + 1;
    uint8_t resp_plain[12];
    resp_plain[0] = (uint8_t)(resp_counter & 0xFF);
    resp_plain[1] = (uint8_t)(resp_counter >> 8);
    memcpy(resp_plain + 2, instance->r1, 8);
    resp_plain[10] = sf1;
    resp_plain[11] = sf2;

    // PKCS#5 pad data(12) first → 16 bytes, compute MAC over padded, append MAC
    uint8_t padded_data[16 + 8];
    size_t padded_data_len = felica_std_pkcs5_pad(resp_plain, 12, padded_data);
    // final_pkt_len = 1(len)+1(code)+8(IDm)+padded_data_len+8(MAC)
    uint8_t final_pkt_len = (uint8_t)(1 + 1 + 8 + padded_data_len + 8);
    uint8_t resp_mac[8];
    felica_std_compute_mac(
        final_pkt_len, FELICA_CMD_WRITE_ENCRYPTED_RESP, padded_data, padded_data_len, resp_mac);

    // Encrypt block = [padded_data][MAC]
    uint8_t full[sizeof(padded_data) + 8];
    memcpy(full, padded_data, padded_data_len);
    memcpy(full + padded_data_len, resp_mac, 8);
    size_t full_len = padded_data_len + 8;
    uint8_t enc_resp[sizeof(full)];
    memset(iv, 0, 8);
    felica_std_des_cbc_encrypt(instance->r2, iv, full, enc_resp, full_len);

    uint8_t resp_buf[42];
    resp_buf[0] = final_pkt_len;
    resp_buf[1] = FELICA_CMD_WRITE_ENCRYPTED_RESP;
    memcpy(resp_buf + 2, instance->data->idm.data, 8);
    memcpy(resp_buf + 10, enc_resp, full_len);

    bit_buffer_reset(instance->tx_buffer);
    bit_buffer_append_bytes(instance->tx_buffer, resp_buf, final_pkt_len);
    return felica_listener_frame_exchange(instance, instance->tx_buffer);
}

// ---------------------------------------------------------------------------
// Secure Read handler (command 0x14)
// Request:  Length + 0x14 + Encrypt(null_pad(counter(2)+R1(8)+blk_cnt(1)+blk_list)+MAC(8))
// Response: Length + 0x15 + Encrypt(pkcs5_pad(counter+1(2)+R1(8)+SF1(1)+SF2(1)+blk_cnt(1)+blk_data)+MAC(8))
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

    // Minimum: counter(2)+R1(8)+blk_cnt(1)+[null_pad]+MAC(8) = at least 24 bytes encrypted
    if(enc_len < 24) return FelicaErrorProtocol;
    uint16_t counter = (uint16_t)(decrypted[0] | ((uint16_t)decrypted[1] << 8));
    if(counter <= instance->des_comm_counter) return FelicaErrorProtocol;
    if(memcmp(decrypted + 2, instance->r1, 8) != 0) return FelicaErrorProtocol;

    // MAC covers all bytes except last 8 (null_pad is included in MAC-covered data)
    uint8_t expected_mac[8];
    size_t mac_data_len = enc_len - 8;
    felica_std_compute_mac(pkt_len, FELICA_CMD_READ, decrypted, mac_data_len, expected_mac);
    if(memcmp(expected_mac, decrypted + mac_data_len, 8) != 0) return FelicaErrorProtocol;

    instance->des_comm_counter = counter;

    // Parse block list: offset 10 = past counter(2)+R1(8)
    uint8_t inner_off = 10;
    uint8_t blk_cnt = decrypted[inner_off++];
    if(blk_cnt > FELICA_STANDARD_ENCRYPTED_READ_BLOCK_MAX)
        blk_cnt = FELICA_STANDARD_ENCRYPTED_READ_BLOCK_MAX;

    const FelicaSystem* system = NULL;
    if(simple_array_get_count(instance->data->systems) > 0)
        system = simple_array_cget(instance->data->systems, instance->auth_system_idx);

    uint8_t sf1 = 0, sf2 = 0;
    uint8_t block_data[FELICA_STANDARD_ENCRYPTED_READ_BLOCK_MAX][FELICA_DATA_BLOCK_SIZE];
    uint8_t actual_cnt = 0;

    for(uint8_t i = 0; i < blk_cnt; i++) {
        uint8_t svc_idx = decrypted[inner_off] & 0x0F;
        bool is_2byte = (decrypted[inner_off] >> 7) != 0;
        uint8_t blk_num;
        if(is_2byte) {
            blk_num = decrypted[inner_off + 1];
            inner_off += 2;
        } else {
            blk_num = decrypted[inner_off + 1];
            inner_off += 3;
        }
        if(svc_idx >= instance->auth_service_count || !system) {
            sf1 = 0xFF;
            sf2 = 0xA8;
            break;
        }
        uint16_t svc_code = instance->auth_service_codes[svc_idx];
        bool found = false;
        uint32_t pb_count = simple_array_get_count(system->public_blocks);
        for(uint32_t j = 0; j < pb_count; j++) {
            const FelicaPublicBlock* pb = simple_array_cget(system->public_blocks, j);
            if(pb->service_code == svc_code && pb->block_idx == blk_num) {
                memcpy(block_data[actual_cnt], pb->block.data, FELICA_DATA_BLOCK_SIZE);
                found = true;
                break;
            }
        }
        if(!found) {
            sf1 = 0xFF;
            sf2 = 0xA8;
            break;
        }
        actual_cnt++;
    }

    // Build response plaintext: counter+1(2)+R1(8)+SF1(1)+SF2(1)+[blk_cnt(1)+blk_data]
    uint16_t resp_counter = counter + 1;
    uint8_t resp_plain[2 + 8 + 1 + 1 + 1 + FELICA_STANDARD_ENCRYPTED_READ_BLOCK_MAX * FELICA_DATA_BLOCK_SIZE];
    size_t resp_plain_len = 0;
    resp_plain[resp_plain_len++] = (uint8_t)(resp_counter & 0xFF);
    resp_plain[resp_plain_len++] = (uint8_t)(resp_counter >> 8);
    memcpy(resp_plain + resp_plain_len, instance->r1, 8);
    resp_plain_len += 8;
    resp_plain[resp_plain_len++] = sf1;
    resp_plain[resp_plain_len++] = sf2;
    if(sf1 == 0) {
        resp_plain[resp_plain_len++] = actual_cnt;
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
    felica_std_compute_mac(final_pkt_len, FELICA_CMD_READ_RESP, padded_data, padded_data_len, resp_mac);

    uint8_t full[sizeof(padded_data) + 8];
    memcpy(full, padded_data, padded_data_len);
    memcpy(full + padded_data_len, resp_mac, 8);
    size_t full_len = padded_data_len + 8;
    uint8_t enc_resp[sizeof(full)];
    memset(iv, 0, 8);
    felica_std_des_cbc_encrypt(instance->r2, iv, full, enc_resp, full_len);

    uint8_t resp_buf[128];
    resp_buf[0] = final_pkt_len;
    resp_buf[1] = FELICA_CMD_READ_RESP;
    memcpy(resp_buf + 2, enc_resp, full_len);

    bit_buffer_reset(instance->tx_buffer);
    bit_buffer_append_bytes(instance->tx_buffer, resp_buf, final_pkt_len);
    return felica_listener_frame_exchange(instance, instance->tx_buffer);
}

// ---------------------------------------------------------------------------
// Secure Write handler (command 0x16)
// Request:  Length + 0x16 + Encrypt(null_pad(counter(2)+R1(8)+blk_cnt(1)+blk_list+blk_data(16n))+MAC(8))
// Response: Length + 0x17 + Encrypt(pkcs5_pad(counter+1(2)+R1(8)+SF1(1)+SF2(1))+MAC(8))
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
    uint8_t decrypted[128];
    if(enc_len > sizeof(decrypted)) return FelicaErrorProtocol;
    uint8_t iv[8] = {0};
    felica_std_des_cbc_decrypt(instance->r2, iv, enc_payload, decrypted, enc_len);

    if(enc_len < 24) return FelicaErrorProtocol;
    uint16_t counter = (uint16_t)(decrypted[0] | ((uint16_t)decrypted[1] << 8));
    if(counter <= instance->des_comm_counter) return FelicaErrorProtocol;
    if(memcmp(decrypted + 2, instance->r1, 8) != 0) return FelicaErrorProtocol;

    // MAC covers all bytes except last 8
    uint8_t expected_mac[8];
    size_t mac_data_len = enc_len - 8;
    felica_std_compute_mac(pkt_len, FELICA_CMD_WRITE, decrypted, mac_data_len, expected_mac);
    if(memcmp(expected_mac, decrypted + mac_data_len, 8) != 0) return FelicaErrorProtocol;

    instance->des_comm_counter = counter;

    // Parse block list: offset 10 = past counter(2)+R1(8)
    uint8_t inner_off = 10;
    uint8_t blk_cnt = decrypted[inner_off++];
    if(blk_cnt > 8) blk_cnt = 8;

    struct {
        uint16_t svc_code;
        uint8_t blk_num;
    } targets[8];
    uint8_t valid_cnt = 0;
    uint8_t sf1 = 0, sf2 = 0;

    for(uint8_t i = 0; i < blk_cnt; i++) {
        uint8_t svc_idx = decrypted[inner_off] & 0x0F;
        bool is_2byte = (decrypted[inner_off] >> 7) != 0;
        uint8_t blk_num;
        if(is_2byte) {
            blk_num = decrypted[inner_off + 1];
            inner_off += 2;
        } else {
            blk_num = decrypted[inner_off + 1];
            inner_off += 3;
        }
        if(svc_idx >= instance->auth_service_count) {
            sf1 = 0xFF;
            sf2 = 0xA8;
            break;
        }
        targets[valid_cnt].svc_code = instance->auth_service_codes[svc_idx];
        targets[valid_cnt].blk_num = blk_num;
        valid_cnt++;
    }

    // Write block data if no error yet
    const FelicaSystem* system = NULL;
    if(simple_array_get_count(instance->data->systems) > 0)
        system = simple_array_cget(instance->data->systems, instance->auth_system_idx);

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
            bool found = false;
            uint32_t pb_count = simple_array_get_count(system->public_blocks);
            for(uint32_t j = 0; j < pb_count; j++) {
                FelicaPublicBlock* pb = simple_array_get(system->public_blocks, j);
                if(pb->service_code == targets[i].svc_code && pb->block_idx == targets[i].blk_num) {
                    memcpy(
                        pb->block.data,
                        decrypted + inner_off + i * FELICA_DATA_BLOCK_SIZE,
                        FELICA_DATA_BLOCK_SIZE);
                    found = true;
                    break;
                }
            }
            if(!found) {
                sf1 = 0xFF;
                sf2 = 0xA8;
                break;
            }
        }
    }

    // Build response: counter+1(2)+R1(8)+SF1(1)+SF2(1) = 12 bytes
    uint16_t resp_counter = counter + 1;
    uint8_t resp_plain[12];
    resp_plain[0] = (uint8_t)(resp_counter & 0xFF);
    resp_plain[1] = (uint8_t)(resp_counter >> 8);
    memcpy(resp_plain + 2, instance->r1, 8);
    resp_plain[10] = sf1;
    resp_plain[11] = sf2;

    // PKCS#5 pad data(12→16), compute MAC over padded, append MAC
    uint8_t padded_data[16 + 8];
    size_t padded_data_len = felica_std_pkcs5_pad(resp_plain, 12, padded_data);
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
    case FELICA_CMD_READ_ENCRYPTED:
        if(instance->data->workflow_type == FelicaStandard) {
            return felica_listener_command_handler_encrypted_read(instance, generic_request);
        }
        return FelicaErrorNotPresent;
    case FELICA_CMD_WRITE_ENCRYPTED:
        if(instance->data->workflow_type == FelicaStandard) {
            return felica_listener_command_handler_encrypted_write(instance, generic_request);
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

            if(request->header.code == FELICA_LISTENER_CMD_POLLING) {
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
            } else if(!felica_listener_check_idm(instance, &request->header.idm)) {
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
