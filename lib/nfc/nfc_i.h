/**
 * @file nfc_i.h
 * @brief NFC private interface definitions.
 *
 * This file is an implementation detail and is not part of the external-app SDK.
 */
#pragma once

#include "nfc.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Enable or disable automatic SENSF_RES transmission in FeliCa listener mode. */
NfcError nfc_felica_listener_set_sensf_res_enabled(Nfc* instance, bool enabled);

#ifdef __cplusplus
}
#endif
