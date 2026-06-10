#include "felica_listener_i.h"

#include "nfc/protocols/nfc_listener_base.h"
#include <nfc/helpers/felica_crc.h>
#include <furi_hal_nfc.h>
#include <furi_hal_random.h>
#include <mbedtls/include/mbedtls/des.h>

#define FELICA_LISTENER_MAX_BUFFER_SIZE     (256)
#define FELICA_LISTENER_CMD_POLLING         (0x00U)
#define FELICA_LISTENER_RESPONSE_POLLING    (0x01U)
#define FELICA_LISTENER_RESPONSE_CODE_READ  (0x07)
#define FELICA_LISTENER_RESPONSE_CODE_WRITE (0x09)

// Auth2 response: 1(len) + 1(0x13) + 40(encrypted, 32 plaintext + 8 PKCS#5) = 42 bytes
#define FELICA_STD_AUTH2_RESP_PAYLOAD_LEN (40U)
#define FELICA_STD_AUTH2_RESP_TOTAL_LEN   (2U + FELICA_STD_AUTH2_RESP_PAYLOAD_LEN)

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
    nfc_config(instance->nfc, NfcModeListener, NfcTechFelica);
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

// ─── FeliCa Standard auth crypto helpers (listener-internal) ─────────────────

static void felica_std_des_ecb_encrypt(
    const uint8_t key[FELICA_STD_KEY_SIZE],
    const uint8_t data[FELICA_STD_KEY_SIZE],
    uint8_t out[FELICA_STD_KEY_SIZE]) {
    mbedtls_des_context ctx;
    mbedtls_des_init(&ctx);
    mbedtls_des_setkey_enc(&ctx, key);
    mbedtls_des_crypt_ecb(&ctx, data, out);
    mbedtls_des_free(&ctx);
}

static void felica_std_des_ecb_decrypt(
    const uint8_t key[FELICA_STD_KEY_SIZE],
    const uint8_t data[FELICA_STD_KEY_SIZE],
    uint8_t out[FELICA_STD_KEY_SIZE]) {
    mbedtls_des_context ctx;
    mbedtls_des_init(&ctx);
    mbedtls_des_setkey_dec(&ctx, key);
    mbedtls_des_crypt_ecb(&ctx, data, out);
    mbedtls_des_free(&ctx);
}

static void felica_std_des_cbc_encrypt(
    const uint8_t key[FELICA_STD_KEY_SIZE],
    const uint8_t iv[FELICA_STD_KEY_SIZE],
    const uint8_t* data,
    size_t len,
    uint8_t* out) {
    mbedtls_des_context ctx;
    mbedtls_des_init(&ctx);
    mbedtls_des_setkey_enc(&ctx, key);
    uint8_t iv_copy[FELICA_STD_KEY_SIZE];
    memcpy(iv_copy, iv, FELICA_STD_KEY_SIZE);
    mbedtls_des_crypt_cbc(&ctx, MBEDTLS_DES_ENCRYPT, len, iv_copy, data, out);
    mbedtls_des_free(&ctx);
}

// MAC: fold padded_header=[length, cmd_code, 0...] using each data block as DES key
static void felica_std_calc_mac(
    uint8_t length,
    uint8_t cmd_code,
    const uint8_t* data_blocks,
    uint8_t block_count,
    uint8_t mac[FELICA_STD_KEY_SIZE]) {
    uint8_t running[FELICA_STD_KEY_SIZE];
    running[0] = length;
    running[1] = cmd_code;
    memset(running + 2, 0, 6);
    for(uint8_t i = 0; i < block_count; i++) {
        uint8_t tmp[FELICA_STD_KEY_SIZE];
        felica_std_des_ecb_encrypt(data_blocks + (size_t)i * FELICA_STD_KEY_SIZE, running, tmp);
        memcpy(running, tmp, FELICA_STD_KEY_SIZE);
    }
    memcpy(mac, running, FELICA_STD_KEY_SIZE);
}

static void felica_std_derive_group_service_key(
    const FelicaSystem* system,
    const uint16_t* area_codes,
    uint8_t area_count,
    uint8_t gsk[FELICA_STD_KEY_SIZE]) {
    if(!system->has_system_key) {
        memset(gsk, 0, FELICA_STD_KEY_SIZE);
        return;
    }
    memcpy(gsk, system->system_key, FELICA_STD_KEY_SIZE);
    size_t total = simple_array_get_count(system->areas);
    for(uint8_t ri = 0; ri < area_count; ri++) {
        uint16_t req_code = area_codes[ri];
        for(size_t a = 0; a < total; a++) {
            const FelicaArea* area = simple_array_get(system->areas, a);
            if(area->code == req_code && area->has_key) {
                uint8_t tmp[FELICA_STD_KEY_SIZE];
                felica_std_des_ecb_encrypt(area->key, gsk, tmp);
                memcpy(gsk, tmp, FELICA_STD_KEY_SIZE);
                break;
            }
        }
    }
}

static void felica_std_derive_user_service_key(
    const FelicaSystem* system,
    const uint8_t gsk[FELICA_STD_KEY_SIZE],
    const uint16_t* service_codes,
    uint8_t service_count,
    uint8_t usk[FELICA_STD_KEY_SIZE]) {
    memcpy(usk, gsk, FELICA_STD_KEY_SIZE);
    size_t total = simple_array_get_count(system->services);
    for(uint8_t ri = 0; ri < service_count; ri++) {
        uint16_t req_code = service_codes[ri];
        for(size_t s = 0; s < total; s++) {
            const FelicaService* svc = simple_array_get(system->services, s);
            if(svc->code == req_code && svc->has_key) {
                uint8_t tmp[FELICA_STD_KEY_SIZE];
                felica_std_des_ecb_encrypt(svc->key, usk, tmp);
                memcpy(usk, tmp, FELICA_STD_KEY_SIZE);
                break;
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────

/** Find the system that contains the given area code. Returns NULL if not found. */
static const FelicaSystem*
    felica_listener_find_system_by_area(const FelicaData* data, uint16_t area_code) {
    size_t sys_count = simple_array_get_count(data->systems);
    for(size_t s = 0; s < sys_count; s++) {
        const FelicaSystem* sys = simple_array_get(data->systems, s);
        size_t area_count = simple_array_get_count(sys->areas);
        for(size_t a = 0; a < area_count; a++) {
            const FelicaArea* area = simple_array_get(sys->areas, a);
            if(area->code == area_code) return sys;
        }
    }
    return NULL;
}

/**
 * Authentication1 handler (command code 0x10).
 *
 * Request format (no IDm):
 *   [0]     length
 *   [1]     0x10
 *   [2]     n  (area count)
 *   [3 .. 2+2n]            area codes (2 bytes each, LE)
 *   [3+2n]  o  (service count)
 *   [4+2n .. 3+2n+2o]      service codes (2 bytes each, LE)
 *   [4+2n+2o .. 11+2n+2o]  1A (8 bytes, DES-ECB(R1, USK) from reader)
 *
 * Response format (no IDm):
 *   [0]   18  (length)
 *   [1]   0x11
 *   [2-9] 1B  (DES-ECB(R1, USK) – proved we can decrypt)
 *   [10-17] 2A  (DES-ECB(R2, GSK_XOR_IDm) – our challenge to reader)
 */
static FelicaError felica_listener_command_handler_auth1(
    FelicaListener* instance,
    const FelicaListenerGenericRequest* const generic_request) {
    FURI_LOG_D(TAG, "Auth1 cmd");

    const uint8_t* buf = (const uint8_t*)generic_request;
    // buf[0]=length, buf[1]=0x10, buf[2]=n
    uint8_t n = buf[2];
    const uint16_t* area_codes = (const uint16_t*)&buf[3];
    uint8_t o = buf[3 + 2 * n];
    const uint16_t* service_codes = (const uint16_t*)&buf[4 + 2 * n];
    const uint8_t* one_a = &buf[4 + 2 * n + 2 * o];

    // Find the system by first area code
    const FelicaSystem* system = NULL;
    if(n > 0) {
        system = felica_listener_find_system_by_area(instance->data, area_codes[0]);
    }
    // Fall back to first system if no area match
    if(!system && simple_array_get_count(instance->data->systems) > 0) {
        system = simple_array_get(instance->data->systems, 0);
    }

    if(!system || !system->has_system_key) {
        FURI_LOG_W(TAG, "Auth1: no system key, skipping");
        return FelicaErrorProtocol;
    }

    // Derive Group Service Key: DES_ENC^(area_keys)(system_key)
    uint8_t gsk[FELICA_STD_KEY_SIZE];
    felica_std_derive_group_service_key(system, area_codes, n, gsk);

    // Derive User Service Key: DES_ENC^(service_keys)(gsk)
    uint8_t usk[FELICA_STD_KEY_SIZE];
    felica_std_derive_user_service_key(system, gsk, service_codes, o, usk);

    // Decrypt 1A → R1 using User Service Key
    uint8_t r1[FELICA_STD_CHALLENGE_SIZE];
    felica_std_des_ecb_decrypt(usk, one_a, r1);

    // 1B = DES_ENC(R1, USK)  (same as 1A when ECB; proves card knows USK)
    uint8_t one_b[FELICA_STD_CHALLENGE_SIZE];
    felica_std_des_ecb_encrypt(usk, r1, one_b);

    // Generate random R2
    uint8_t r2[FELICA_STD_CHALLENGE_SIZE];
    furi_hal_random_fill_buf(r2, FELICA_STD_CHALLENGE_SIZE);

    // Group Service Key XOR IDm
    uint8_t gsk_xor_idm[FELICA_STD_KEY_SIZE];
    for(uint8_t i = 0; i < FELICA_STD_KEY_SIZE; i++) {
        gsk_xor_idm[i] = gsk[i] ^ instance->data->idm.data[i];
    }

    // 2A = DES_ENC(R2, GSK_XOR_IDm)
    uint8_t two_a[FELICA_STD_CHALLENGE_SIZE];
    felica_std_des_ecb_encrypt(gsk_xor_idm, r2, two_a);

    // Save authentication state
    instance->std_auth.state = FelicaStdAuthAuth1Done;
    memcpy(instance->std_auth.r1, r1, FELICA_STD_CHALLENGE_SIZE);
    memcpy(instance->std_auth.r2, r2, FELICA_STD_CHALLENGE_SIZE);
    memcpy(instance->std_auth.user_service_key, usk, FELICA_STD_KEY_SIZE);
    memcpy(instance->std_auth.gsk_xor_idm, gsk_xor_idm, FELICA_STD_KEY_SIZE);
    instance->std_auth.counter = 0;
    instance->std_auth.authorized_service_count =
        (o <= FELICA_STD_MAX_AUTH_SERVICES) ? o : FELICA_STD_MAX_AUTH_SERVICES;
    for(uint8_t i = 0; i < instance->std_auth.authorized_service_count; i++) {
        instance->std_auth.authorized_services[i] = service_codes[i];
    }

    // Build response: [length=18][0x11][1B(8)][2A(8)]
    uint8_t resp[18];
    resp[0] = 18;
    resp[1] = FELICA_CMD_AUTHENTICATION1_RESP;
    memcpy(&resp[2], one_b, FELICA_STD_CHALLENGE_SIZE);
    memcpy(&resp[10], two_a, FELICA_STD_CHALLENGE_SIZE);

    bit_buffer_reset(instance->tx_buffer);
    bit_buffer_append_bytes(instance->tx_buffer, resp, sizeof(resp));
    return felica_listener_frame_exchange(instance, instance->tx_buffer);
}

/**
 * Authentication2 handler (command code 0x12).
 *
 * Request format (no IDm):
 *   [0]    length
 *   [1]    0x12
 *   [2-9]  2B  (DES-ECB(R2, GSK_XOR_IDm) echoed back from reader)
 *
 * Response format (no IDm):
 *   [0]    42  (length)
 *   [1]    0x13
 *   [2-41] DES-CBC(R2, IV=0, PKCS#5_pad(counter(2) + R1[0:5](6) + IDm(8) + PMm(8) + MAC(8)))
 */
static FelicaError felica_listener_command_handler_auth2(
    FelicaListener* instance,
    const FelicaListenerGenericRequest* const generic_request) {
    FURI_LOG_D(TAG, "Auth2 cmd");

    if(instance->std_auth.state != FelicaStdAuthAuth1Done) {
        FURI_LOG_W(TAG, "Auth2 received without prior Auth1");
        return FelicaErrorProtocol;
    }

    const uint8_t* buf = (const uint8_t*)generic_request;
    const uint8_t* two_b = &buf[2];

    // Decrypt 2B with GSK_XOR_IDm → R2_received
    uint8_t r2_received[FELICA_STD_CHALLENGE_SIZE];
    felica_std_des_ecb_decrypt(instance->std_auth.gsk_xor_idm, two_b, r2_received);

    // Verify R2
    if(memcmp(r2_received, instance->std_auth.r2, FELICA_STD_CHALLENGE_SIZE) != 0) {
        FURI_LOG_W(TAG, "Auth2: R2 mismatch");
        instance->std_auth.state = FelicaStdAuthIdle;
        return FelicaErrorProtocol;
    }

    // Authentication successful
    instance->std_auth.state = FelicaStdAuthAuthenticated;
    instance->std_auth.counter = 1;

    // Build plaintext: counter(2 LE) + R1[0:5](6) + IDm(8) + PMm(8) = 24 bytes
    // Then MAC(8) = 32 bytes total, then PKCS#5 pad to 40 bytes
    uint8_t plaintext[32];
    plaintext[0] = (uint8_t)(instance->std_auth.counter & 0xFF);
    plaintext[1] = (uint8_t)(instance->std_auth.counter >> 8);
    memcpy(&plaintext[2], instance->std_auth.r1, 6);
    memcpy(&plaintext[8], instance->data->idm.data, FELICA_IDM_SIZE);
    memcpy(&plaintext[16], instance->data->pmm.data, FELICA_PMM_SIZE);

    // MAC: fold padded_header using each plaintext block as DES key
    // padded_header = [total_response_len, 0x13, 0, 0, 0, 0, 0, 0]
    // Plaintext data blocks (3 × 8 bytes): counter+R1[0:5], IDm, PMm
    uint8_t mac[FELICA_STD_KEY_SIZE];
    felica_std_calc_mac(
        FELICA_STD_AUTH2_RESP_TOTAL_LEN, FELICA_CMD_AUTHENTICATION2_RESP, plaintext, 3, mac);
    memcpy(&plaintext[24], mac, FELICA_STD_KEY_SIZE);

    // PKCS#5 pad: 32 bytes → add 8 bytes of 0x08 → 40 bytes
    uint8_t padded[FELICA_STD_AUTH2_RESP_PAYLOAD_LEN];
    memcpy(padded, plaintext, 32);
    memset(&padded[32], 0x08, 8);

    // Encrypt: DES-CBC with R2 as key, IV = 0
    uint8_t encrypted[FELICA_STD_AUTH2_RESP_PAYLOAD_LEN];
    uint8_t iv[FELICA_STD_KEY_SIZE];
    memset(iv, 0, sizeof(iv));
    felica_std_des_cbc_encrypt(
        instance->std_auth.r2, iv, padded, FELICA_STD_AUTH2_RESP_PAYLOAD_LEN, encrypted);

    // Build response: [length=42][0x13][encrypted(40)]
    uint8_t resp[FELICA_STD_AUTH2_RESP_TOTAL_LEN];
    resp[0] = FELICA_STD_AUTH2_RESP_TOTAL_LEN;
    resp[1] = FELICA_CMD_AUTHENTICATION2_RESP;
    memcpy(&resp[2], encrypted, FELICA_STD_AUTH2_RESP_PAYLOAD_LEN);

    bit_buffer_reset(instance->tx_buffer);
    bit_buffer_append_bytes(instance->tx_buffer, resp, sizeof(resp));
    return felica_listener_frame_exchange(instance, instance->tx_buffer);
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

static FelicaError felica_listener_process_request(
    FelicaListener* instance,
    const FelicaListenerGenericRequest* generic_request) {
    const uint8_t cmd_code = generic_request->header.code;
    switch(cmd_code) {
    case FELICA_CMD_READ_WITHOUT_ENCRYPTION:
        return felica_listener_command_handler_read(instance, generic_request);
    case FELICA_CMD_WRITE_WITHOUT_ENCRYPTION:
        return felica_listener_command_handler_write(instance, generic_request);
    default:
        FURI_LOG_E(TAG, "FeliCa incorrect command");
        return FelicaErrorNotPresent;
    }
}

static void felica_listener_populate_polling_response_header(
    FelicaListener* instance,
    FelicaListenerPollingResponseHeader* resp) {
    resp->idm = instance->data->idm;
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

static uint16_t felica_listener_get_response_system_code(
    FelicaListener* instance,
    const FelicaListenerGenericRequest* const generic_request) {
    uint16_t resp_system_code = FELICA_SYSTEM_CODE_CODE;
    if(felica_listener_check_system_code(generic_request, FELICA_LISTENER_SYSTEM_CODE_NDEF) &&
       instance->data->data.fs.mc.data[FELICA_MC_SYS_OP] == 1) {
        // NDEF
        resp_system_code = FELICA_LISTENER_SYSTEM_CODE_NDEF;
    } else if(felica_listener_check_system_code(
                  generic_request, FELICA_LISTENER_SYSTEM_CODE_LITES)) {
        // Lite-S
        resp_system_code = FELICA_LISTENER_SYSTEM_CODE_LITES;
    }
    return resp_system_code;
}

static FelicaError felica_listener_process_system_code(
    FelicaListener* instance,
    const FelicaListenerGenericRequest* const generic_request) {
    FelicaError result = FelicaErrorFeatureUnsupported;
    do {
        uint16_t resp_system_code =
            felica_listener_get_response_system_code(instance, generic_request);
        if(resp_system_code == FELICA_SYSTEM_CODE_CODE) break;

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
            if(request->length != size) {
                FURI_LOG_E(TAG, "Wrong request length");
                break;
            }

            uint8_t cmd_code = request->header.code;

            if(cmd_code == FELICA_LISTENER_CMD_POLLING) {
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
            } else if(cmd_code == FELICA_CMD_AUTHENTICATION1) {
                FelicaError error = felica_listener_command_handler_auth1(instance, request);
                if(error != FelicaErrorNone) {
                    FURI_LOG_E(TAG, "Auth1 error: %2X", error);
                }
            } else if(cmd_code == FELICA_CMD_AUTHENTICATION2) {
                FelicaError error = felica_listener_command_handler_auth2(instance, request);
                if(error != FelicaErrorNone) {
                    FURI_LOG_E(TAG, "Auth2 error: %2X", error);
                }
            } else {
                if(!felica_listener_check_block_list_size(instance, request)) {
                    FURI_LOG_E(TAG, "Wrong request length");
                    break;
                }
                if(!felica_listener_check_idm(instance, &request->header.idm)) {
                    FURI_LOG_E(TAG, "Wrong IDm");
                    break;
                }
                FelicaError error = felica_listener_process_request(instance, request);
                if(error != FelicaErrorNone) {
                    FURI_LOG_E(TAG, "Processing error: %2X", error);
                }
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
