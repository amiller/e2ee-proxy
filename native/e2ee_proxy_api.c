/*
 * E2EE Proxy API Implementation
 */

#include "e2ee_proxy_api.h"
#include "embedded_certs.h"
#include "secure_crypto.h"

/* ML-KEM-768 low-level API (from mlkem/api.h with KYBER_K=3) */
#define CRYPTO_PUBLICKEYBYTES  1184
#define CRYPTO_SECRETKEYBYTES  2400
#define CRYPTO_CIPHERTEXTBYTES 1088
#define CRYPTO_BYTES           32

extern int pqcrystals_kyber768_ref_keypair(uint8_t *pk, uint8_t *sk);
extern int pqcrystals_kyber768_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int pqcrystals_kyber768_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <zlib.h>
#include <stdatomic.h>

static atomic_int g_initialized = 0;

PROTECT_FULL
int e2ee_init(void) {
    if (atomic_exchange(&g_initialized, 1) != 0) {
        return 0;
    }

    secure_key_init();
    return 0;
}

PROTECT_FULL
int e2ee_get_cert_der(uint8_t *out, size_t *len) {
    if (!atomic_load(&g_initialized)) return -1;
    if (*len < EMBEDDED_CERT_LEN) {
        *len = EMBEDDED_CERT_LEN;
        return -1;
    }
    memcpy(out, EMBEDDED_CERT, EMBEDDED_CERT_LEN);
    *len = EMBEDDED_CERT_LEN;
    return 0;
}

PROTECT_FULL
int e2ee_get_intermediate_der(uint8_t *out, size_t *len) {
    if (!atomic_load(&g_initialized)) return -1;
    if (*len < EMBEDDED_INTERMEDIATE_LEN) {
        *len = EMBEDDED_INTERMEDIATE_LEN;
        return -1;
    }
    memcpy(out, EMBEDDED_INTERMEDIATE, EMBEDDED_INTERMEDIATE_LEN);
    *len = EMBEDDED_INTERMEDIATE_LEN;
    return 0;
}

PROTECT_FULL
int e2ee_get_root_der(uint8_t *out, size_t *len) {
    if (!atomic_load(&g_initialized)) return -1;
    if (*len < EMBEDDED_ROOT_LEN) {
        *len = EMBEDDED_ROOT_LEN;
        return -1;
    }
    memcpy(out, EMBEDDED_ROOT, EMBEDDED_ROOT_LEN);
    *len = EMBEDDED_ROOT_LEN;
    return 0;
}

PROTECT_FULL
int e2ee_get_privkey_der(uint8_t *out, size_t *len) {
    if (!atomic_load(&g_initialized)) return -1;
    if (*len < EMBEDDED_PRIVKEY_LEN) {
        *len = EMBEDDED_PRIVKEY_LEN;
        return -1;
    }
    memcpy(out, EMBEDDED_PRIVKEY, EMBEDDED_PRIVKEY_LEN);
    *len = EMBEDDED_PRIVKEY_LEN;
    return 0;
}

int e2ee_mlkem_keygen(uint8_t pk[E2EE_MLKEM_PK_SIZE],
                      uint8_t sk[E2EE_MLKEM_SK_SIZE]) {
    return pqcrystals_kyber768_ref_keypair(pk, sk);
}

int e2ee_mlkem_encapsulate(const uint8_t *pk,
                           uint8_t ct[E2EE_MLKEM_CT_SIZE],
                           uint8_t ss[E2EE_MLKEM_SS_SIZE]) {
    return pqcrystals_kyber768_ref_enc(ct, ss, pk);
}

int e2ee_mlkem_decapsulate(const uint8_t *sk,
                           const uint8_t ct[E2EE_MLKEM_CT_SIZE],
                           uint8_t ss[E2EE_MLKEM_SS_SIZE]) {
    return pqcrystals_kyber768_ref_dec(ss, ct, sk);
}

int e2ee_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                     const uint8_t *salt, size_t salt_len,
                     const uint8_t *info, size_t info_len,
                     uint8_t *okm, size_t okm_len) {
    return hkdf(ikm, ikm_len, salt, salt_len, info, info_len, okm, okm_len);
}

int e2ee_chacha20_seal(const uint8_t key[32], const uint8_t nonce[12],
                       const uint8_t *plaintext, size_t pt_len,
                       uint8_t *ciphertext, uint8_t tag[16]) {
    memcpy(ciphertext, plaintext, pt_len);
    return chacha20_poly1305_seal(key, nonce, NULL, 0, ciphertext, pt_len, tag);
}

int e2ee_chacha20_open(const uint8_t key[32], const uint8_t nonce[12],
                       const uint8_t *ciphertext, size_t ct_len,
                       const uint8_t tag[16], uint8_t *plaintext) {
    memcpy(plaintext, ciphertext, ct_len);
    return chacha20_poly1305_open(key, nonce, NULL, 0, plaintext, ct_len, tag);
}

size_t e2ee_gzip_compress(const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t out_max) {
    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                     15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        return 0;
    }

    strm.next_in = (Bytef *)in;
    strm.avail_in = (uInt)in_len;
    strm.next_out = (Bytef *)out;
    strm.avail_out = (uInt)out_max;

    int ret = deflate(&strm, Z_FINISH);
    size_t compressed_size = strm.total_out;
    deflateEnd(&strm);

    if (ret != Z_STREAM_END) return 0;
    return compressed_size;
}

size_t e2ee_gzip_decompress(const uint8_t *in, size_t in_len,
                            uint8_t *out, size_t out_max) {
    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    if (inflateInit2(&strm, 15 + 32) != Z_OK) {
        return 0;
    }

    strm.next_in = (Bytef *)in;
    strm.avail_in = (uInt)in_len;
    strm.next_out = (Bytef *)out;
    strm.avail_out = (uInt)out_max;

    int ret = inflate(&strm, Z_FINISH);
    size_t decompressed_size = strm.total_out;
    inflateEnd(&strm);

    if (ret != Z_STREAM_END) return 0;
    return decompressed_size;
}

void e2ee_random_bytes(uint8_t *out, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        size_t rd = fread(out, 1, len, f);
        fclose(f);
        if (rd == len) return;
    }
    abort();
}

/* --- DCAP TD-quote verification ---------------------------------------------
 *
 * Reference implementation over Intel's DCAP Quote Verification Library. The
 * security-critical TD report fields the Lua policy depends on are read from the
 * quote body at fixed TDX v4 offsets, only after the QVL has validated the
 * ECDSA signature over that body.
 *
 * TDX v4 quote (sgx_quote4_t): 48-byte header, then the 584-byte TD report body
 * (sgx_report2_body_t). Offsets within the body:
 *   td_attributes @120, mr_td @136, report_data @520.
 */
#include <time.h>
#include "sgx_dcap_quoteverify.h"   /* sgx_qv_verify_quote, sgx_ql_qv_result_t */

#define TDX_BODY_OFF        48
#define TDX_OFF_TD_ATTR     (TDX_BODY_OFF + 120)
#define TDX_OFF_MRTD        (TDX_BODY_OFF + 136)
#define TDX_OFF_REPORT_DATA (TDX_BODY_OFF + 520)
#define TDX_MIN_QUOTE_LEN   (TDX_BODY_OFF + 584)

PROTECT_FULL
int e2ee_verify_td_quote(const uint8_t *quote, size_t quote_len,
                         e2ee_td_report_t *out) {
    if (!quote || !out || quote_len < TDX_MIN_QUOTE_LEN) return -1;

    uint32_t collateral_expiration_status = 1;
    sgx_ql_qv_result_t qv_result = SGX_QL_QV_RESULT_UNSPECIFIED;

    /* p_quote_collateral = NULL -> QPL fetches collateral (PCCS / Intel PCS). */
    quote3_error_t ret = sgx_qv_verify_quote(
        quote, (uint32_t)quote_len,
        NULL,                              /* collateral (QPL-provided) */
        time(NULL),                        /* expiration_check_date */
        &collateral_expiration_status,
        &qv_result,
        NULL, 0, NULL);                    /* no supplemental data */

    if (ret != SGX_QL_SUCCESS) return -2;
    if (collateral_expiration_status != 0) return -3;

    /* Accept OK and SW_HARDENING_NEEDED (benign: SW mitigations recommended,
     * and what most production TDX instances report). Reject CONFIG_NEEDED,
     * OUT_OF_DATE, REVOKED, INVALID_SIGNATURE, etc. tcb_status carries the exact
     * verdict for logging; tighten/loosen this set to change policy. */
    switch (qv_result) {
        case SGX_QL_QV_RESULT_OK:
            out->tcb_status = 0;
            break;
        case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
            out->tcb_status = (uint32_t)qv_result;
            break;
        default:
            return -4;
    }

    memcpy(out->report_data,   quote + TDX_OFF_REPORT_DATA, 64);
    memcpy(out->mrtd,          quote + TDX_OFF_MRTD,         48);
    memcpy(out->td_attributes, quote + TDX_OFF_TD_ATTR,       8);
    return 0;
}
