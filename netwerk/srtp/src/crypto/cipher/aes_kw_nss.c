/*
 * aes_kw.c
 *
 * AES Key Wrap with Padding
 *
 * Richard L. Barnes
 * Cisco Systems, Inc.
 *
 */

/*
 *
 * Copyright (c) 2015, Cisco Systems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 *
 *   Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include "crypto_types.h"
#include "err.h" /* for srtp_debug */
#include "alloc.h"
#include "cipher_types.h"
#include "aes_kw.h"

#include <nss.h>

#define AES_BLOCK_SIZE            16
#define AES_KW_MAX_PLAINTEXT_LEN  0xFFFFFFFF

v256_t probe;

srtp_debug_module_t srtp_mod_aes_kw = {
    0,                      /* debugging is off by default */
    "aes key wrap with NSS" /* printable module name       */
};

static const uint8_t srtp_aes_kw_aiv[4] = {0xA6, 0x59, 0x59, 0xA6};
static const uint8_t srtp_aes_kw_zero[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/*
 * This function allocates a new instance of this crypto engine.
 * The key_len parameter should be one of 16 or 32 for
 * AES-128-KW or AES-256-KW respectively.
 */
static srtp_err_status_t srtp_aes_kw_alloc(srtp_cipher_t **c,
                                           int key_len,
                                           int tlen)
{
    srtp_aes_kw_ctx_t *kw;

    debug_print(srtp_mod_aes_kw, "allocating cipher with key length %d",
                key_len);

    /*
     * Verify the key_len is valid for one of: AES-128/192/256
     */
    if (key_len != SRTP_AES_128_KEY_LEN &&
        key_len != SRTP_AES_256_KEY_LEN) {
        return srtp_err_status_bad_param;
    }

    /* Initialize NSS */
    if (!NSS_IsInitialized() && NSS_NoDB_Init(NULL) != SECSuccess) {
        return (srtp_err_status_cipher_fail);
    }

    /* allocate memory a cipher of type aes_kw */
    *c = (srtp_cipher_t *)srtp_crypto_alloc(sizeof(srtp_cipher_t));
    if (*c == NULL) {
        return srtp_err_status_alloc_fail;
    }

    kw = (srtp_aes_kw_ctx_t *)srtp_crypto_alloc(sizeof(srtp_aes_kw_ctx_t));
    if (kw == NULL) {
        srtp_crypto_free(*c);
        *c = NULL;
        return srtp_err_status_alloc_fail;
    }

    /* set pointers */
    (*c)->state = kw;

    kw->slot = PK11_GetInternalSlot();
    if (!kw->slot) {
      return srtp_err_status_cipher_fail;
    }

    /* setup cipher parameters */
    switch (key_len) {
    case SRTP_AES_128_KEY_LEN:
        (*c)->algorithm = SRTP_AES_KW_128;
        (*c)->type = &srtp_aes_kw_128;
        kw->key_size = SRTP_AES_128_KEY_LEN;
        break;
    case SRTP_AES_256_KEY_LEN:
        (*c)->algorithm = SRTP_AES_KW_256;
        (*c)->type = &srtp_aes_kw_256;
        kw->key_size = SRTP_AES_256_KEY_LEN;
        break;
    }

    /* set key size        */
    (*c)->key_len = key_len;

    return srtp_err_status_ok;
}

/*
 * This function deallocates an AES-KW session.
 */
static srtp_err_status_t srtp_aes_kw_dealloc(srtp_cipher_t *c)
{
    srtp_aes_kw_ctx_t *ctx;

    ctx = (srtp_aes_kw_ctx_t *)c->state;
    if (ctx) {
        if (ctx->slot) {
            PK11_FreeSlot(ctx->slot);
            ctx->slot = NULL;
        }

        if (ctx->key) {
            PK11_FreeSymKey(ctx->key);
            ctx->key = NULL;
        }

        octet_string_set_to_zero(ctx, sizeof(srtp_aes_kw_ctx_t));
        srtp_crypto_free(ctx);
    }

    /* free memory */
    srtp_crypto_free(c);

    return (srtp_err_status_ok);
}

/*
 * aes_gcm_nss_context_init(...) initializes the aes_gcm_context
 * using the value in key[].
 *
 * the key is the secret key
 */
static srtp_err_status_t srtp_aes_kw_context_init(void *cv,
                                                  const uint8_t *key)
{
    srtp_aes_kw_ctx_t *c = (srtp_aes_kw_ctx_t *)cv;

    debug_print(srtp_mod_aes_kw, "key:  %s",
                srtp_octet_string_hex_string(key, c->key_size));


    if (!c->slot) {
        return srtp_err_status_bad_param;
    }

    SECItem keyItem = { siBuffer, (unsigned char *) key, c->key_size };
    c->key = PK11_ImportSymKey(c->slot, CKM_AES_CTR, PK11_OriginUnwrap,
                               CKA_ENCRYPT, &keyItem, NULL);
    if (!c->key) {
        return srtp_err_status_cipher_fail;
    }

    return (srtp_err_status_ok);
}

static srtp_err_status_t srtp_aes_kw_ecb_encrypt(srtp_aes_kw_ctx_t* c, uint8_t *buf) {
    unsigned int len = 16;
    SECStatus rv;

    rv = PK11_Encrypt(c->key, CKM_AES_ECB, NULL,
                      buf, &len, len,
                      buf, len);

    if (rv != SECSuccess) {
        debug_print(srtp_mod_aes_kw, "Error in ECB encryption: %08x", PORT_GetError());
        return srtp_err_status_cipher_fail;
    }

    return srtp_err_status_ok;
}

/*
 * This function encrypts a buffer (in place) using AES KW mode
 */
static srtp_err_status_t srtp_aes_kw_encrypt(void *cv,
                                             unsigned char *buf,
                                             unsigned int *enc_len)
{
    srtp_aes_kw_ctx_t *c = (srtp_aes_kw_ctx_t *)cv;

    /* Check that the plaintext length is acceptable */
    if (!enc_len || *enc_len > AES_KW_MAX_PLAINTEXT_LEN) {
        debug_print(srtp_mod_aes_kw, "plaintext length invalid", *enc_len);
        return srtp_err_status_bad_param;
    }

    /* Pad the plaintext out with zeros */
    int pt_len = *enc_len;
    int r = (pt_len & 0x07)? 8 - (pt_len & 0x07) : 0;
    memset(buf + *enc_len, 0, r);
    *enc_len += r;

    /* Insert the IV and MLI */
    uint32_t mli = htonl(pt_len);
    memmove(buf + 8, buf, *enc_len);
    memcpy(buf, srtp_aes_kw_aiv, sizeof(srtp_aes_kw_aiv));
    memcpy(buf + 4, &mli, 4);
    *enc_len += 8;

    /* If the padded plaintext contains exactly eight octets,
     * prepend the AIV and encrypt
     */
    if (*enc_len == 16) {
        return srtp_aes_kw_ecb_encrypt(c, buf);
    }

    /* Wrap according to RFC 3394 */
    unsigned int i, t, tt;
    int j, k;
    unsigned char *R;
    unsigned char B[16];
    unsigned int n = (*enc_len - 8) >> 3;

    memcpy(B, buf, 8);

    for (j = 0, t = 1; j <= 5; j++) {
        for (i = 1, R = buf + 8; i <= n; i++, t++, R += 8) {
            memcpy(B + 8, R, 8);

            if (srtp_aes_kw_ecb_encrypt(c, B) != srtp_err_status_ok) {
                return srtp_err_status_cipher_fail;
            }

            for (k = 7, tt = t; (k >= 0) && (tt > 0); k--, tt >>= 8) {
                B[k] ^= (unsigned char) (tt & 0xff);
            }

            memcpy(R, B + 8, 8);
        }
    }
    memcpy(buf, B, 8);

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_aes_kw_ecb_decrypt(srtp_aes_kw_ctx_t* c, uint8_t *buf) {
    unsigned int len = 16;
    SECStatus rv;

    rv = PK11_Decrypt(c->key, CKM_AES_ECB, NULL,
                      buf, &len, len,
                      buf, len);

    if (rv != SECSuccess) {
        debug_print(srtp_mod_aes_kw, "Error in ECB decryption: %08x", PORT_GetError());
    }

    return srtp_err_status_ok;
}

/*
 * This function decrypts a buffer (in place) using AES KW mode
 */
static srtp_err_status_t srtp_aes_kw_decrypt(void *cv,
                                             unsigned char *buf,
                                             unsigned int *enc_len)
{
    srtp_aes_kw_ctx_t *c = (srtp_aes_kw_ctx_t *)cv;

    /* Check that the plaintext length is acceptable */
    if (!enc_len || *enc_len == 0 || (*enc_len & 0x07) != 0) {
        debug_print(srtp_mod_aes_kw, "ciphertext length invalid", *enc_len);
        return srtp_err_status_bad_param;
    }

    /* Decrypt the ciphertext */
    if (*enc_len == 16) {
        if (srtp_aes_kw_ecb_decrypt(c, buf) != srtp_err_status_ok) {
            return srtp_err_status_cipher_fail;
        }
    } else {
        unsigned int i, t, tt;
        int j, k;
        unsigned char *R;
        unsigned char B[16];
        unsigned int n = (*enc_len - 8) >> 3;

        memcpy(B, buf, 8);

        for (j = 5, t = 6 * n; j >= 0; j--) {
            for (i = n, R = buf + *enc_len - 8; i >= 1; i--, t--, R -= 8) {
                for (k = 7, tt = t; (k >= 0) && (tt > 0); k--, tt >>= 8) {
                    B[k] ^= (unsigned char) (tt & 0xFF);
                }

                memcpy(B + 8, R, 8);

                if (srtp_aes_kw_ecb_decrypt(c, B) != srtp_err_status_ok) {
                    return srtp_err_status_cipher_fail;
                }

                memcpy(R, B + 8, 8);
            }
        }

        memcpy(buf, B, 8);
    }

    /* Verify the integrity data */
    if (0 != memcmp(buf, srtp_aes_kw_aiv, sizeof(srtp_aes_kw_aiv))) {
        return srtp_err_status_auth_fail;
    }

    uint32_t padded_length = *enc_len - 8;
    uint32_t message_length = ntohl(* (uint32_t*) (buf + 4));
    if (message_length > padded_length || padded_length - message_length > 7) {
        return srtp_err_status_auth_fail;
    }

    if (0 != memcmp(buf + 8 + message_length, srtp_aes_kw_zero, padded_length - message_length)) {
        return srtp_err_status_auth_fail;
    }

    /* Trim the integrity data and padding */
    memmove(buf, buf + 8, message_length);
    *enc_len = message_length;
    return srtp_err_status_ok;
}

/*
 * Name of this crypto engine
 */
static const char srtp_aes_kw_128_description[] =
    "AES-128 KW";
static const char srtp_aes_kw_256_description[] =
    "AES-256 KW";

/* Test cases generated with OpenSSL EVP_aes_128_wrap_pad() etc. */
/* Test keys */
static const uint8_t srtp_aes_kw_key_128[16] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
};

static const uint8_t srtp_aes_kw_key_256[32] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
};

/* Test plaintexts */
static const uint8_t srtp_aes_kw_key_pt_1[1] = {
  0xff
};

static const uint8_t srtp_aes_kw_key_pt_16[16] = {
  0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
  0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
};

static const uint8_t srtp_aes_kw_key_pt_20[20] = {
  0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
  0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
  0x80, 0x81, 0x82, 0x83,
};

/* Test ciphertexts */
static const uint8_t srtp_aes_kw_key_ct_1_128[16] = {
  0x2c, 0xca, 0x36, 0xdd, 0x9a, 0x76, 0xc1, 0x42,
  0x50, 0x2b, 0xc4, 0x36, 0x1e, 0xea, 0x46, 0x0f,
};

static const uint8_t srtp_aes_kw_key_ct_16_128[24] = {
  0x6c, 0x72, 0xf9, 0x9a, 0x49, 0x19, 0x6a, 0x52,
  0x3a, 0xeb, 0x82, 0xed, 0x14, 0x78, 0x6d, 0x29,
  0x8d, 0x06, 0x4b, 0x76, 0x22, 0x9a, 0x0f, 0x29,
};

static const uint8_t srtp_aes_kw_key_ct_20_128[32] = {
  0xf1, 0x81, 0x6c, 0x92, 0xf4, 0x4a, 0x2f, 0x94,
  0x37, 0xd6, 0xbb, 0xd2, 0x04, 0xba, 0xbd, 0x37,
  0xba, 0x11, 0x54, 0x37, 0x77, 0x13, 0xbf, 0x7b,
  0xb7, 0x80, 0x86, 0x96, 0x72, 0xf3, 0x7d, 0x64,
};

static const uint8_t srtp_aes_kw_key_ct_1_256[16] = {
  0x7b, 0x96, 0x53, 0x7c, 0xe2, 0xff, 0xc1, 0xee,
  0x73, 0x3b, 0xf8, 0x69, 0xbe, 0x52, 0xdd, 0x44,
};

static const uint8_t srtp_aes_kw_key_ct_16_256[24] = {
  0x05, 0xd1, 0xf8, 0xa5, 0x86, 0x8f, 0xeb, 0x72,
  0x29, 0xab, 0xc1, 0xf7, 0x1c, 0x12, 0xda, 0xa4,
  0xc5, 0x82, 0xbd, 0x46, 0x42, 0x8d, 0x39, 0x70,
};

static const uint8_t srtp_aes_kw_key_ct_20_256[32] = {
  0xe5, 0xa7, 0x93, 0xb7, 0x81, 0x5c, 0x75, 0x61,
  0x14, 0xa2, 0x0c, 0x55, 0xbd, 0xe0, 0x3e, 0x1a,
  0x81, 0xfa, 0x8e, 0x2a, 0xf0, 0xc7, 0x90, 0xc6,
  0x79, 0x5d, 0x01, 0x4c, 0x7c, 0x6c, 0x57, 0x9f,
};

static const srtp_cipher_test_case_t srtp_aes_kw_test_case_128_1 = {
    SRTP_AES_128_KEY_LEN,         /* octets in key            */
    srtp_aes_kw_key_128,          /* key                      */
    NULL,                         /* iv                       */
    1,                            /* octets in plaintext      */
    srtp_aes_kw_key_pt_1,         /* plaintext                */
    16,                           /* octets in ciphertext     */
    srtp_aes_kw_key_ct_1_128,     /* ciphertext  + tag        */
    0,                            /* octets in AAD            */
    NULL,                         /* AAD                      */
    0,                            /* octets in tag            */
    NULL                          /* pointer to next testcase */
};

static const srtp_cipher_test_case_t srtp_aes_kw_test_case_128_16 = {
    SRTP_AES_128_KEY_LEN,         /* octets in key            */
    srtp_aes_kw_key_128,          /* key                      */
    NULL,                         /* iv                       */
    16,                           /* octets in plaintext      */
    srtp_aes_kw_key_pt_16,        /* plaintext                */
    24,                           /* octets in ciphertext     */
    srtp_aes_kw_key_ct_16_128,    /* ciphertext  + tag        */
    0,                            /* octets in AAD            */
    NULL,                         /* AAD                      */
    0,                            /* octets in tag            */
    &srtp_aes_kw_test_case_128_1  /* pointer to next testcase */
};

static const srtp_cipher_test_case_t srtp_aes_kw_test_case_128_20 = {
    SRTP_AES_128_KEY_LEN,         /* octets in key            */
    srtp_aes_kw_key_128,          /* key                      */
    NULL,                         /* iv                       */
    20,                           /* octets in plaintext      */
    srtp_aes_kw_key_pt_20,        /* plaintext                */
    32,                           /* octets in ciphertext     */
    srtp_aes_kw_key_ct_20_128,    /* ciphertext  + tag        */
    0,                            /* octets in AAD            */
    NULL,                         /* AAD                      */
    0,                            /* octets in tag            */
    &srtp_aes_kw_test_case_128_16 /* pointer to next testcase */
};

static const srtp_cipher_test_case_t srtp_aes_kw_test_case_256_1 = {
    SRTP_AES_256_KEY_LEN,         /* octets in key            */
    srtp_aes_kw_key_256,          /* key                      */
    NULL,                         /* iv                       */
    1,                            /* octets in plaintext      */
    srtp_aes_kw_key_pt_1,         /* plaintext                */
    16,                           /* octets in ciphertext     */
    srtp_aes_kw_key_ct_1_256,     /* ciphertext  + tag        */
    0,                            /* octets in AAD            */
    NULL,                         /* AAD                      */
    0,                            /* octets in tag            */
    NULL                          /* pointer to next testcase */
};

static const srtp_cipher_test_case_t srtp_aes_kw_test_case_256_16 = {
    SRTP_AES_256_KEY_LEN,         /* octets in key            */
    srtp_aes_kw_key_256,          /* key                      */
    NULL,                         /* iv                       */
    16,                           /* octets in plaintext      */
    srtp_aes_kw_key_pt_16,        /* plaintext                */
    24,                           /* octets in ciphertext     */
    srtp_aes_kw_key_ct_16_256,    /* ciphertext  + tag        */
    0,                            /* octets in AAD            */
    NULL,                         /* AAD                      */
    0,                            /* octets in tag            */
    &srtp_aes_kw_test_case_256_1  /* pointer to next testcase */
};

static const srtp_cipher_test_case_t srtp_aes_kw_test_case_256_20 = {
    SRTP_AES_256_KEY_LEN,         /* octets in key            */
    srtp_aes_kw_key_256,          /* key                      */
    NULL,                         /* iv                       */
    20,                           /* octets in plaintext      */
    srtp_aes_kw_key_pt_20,        /* plaintext                */
    32,                           /* octets in ciphertext     */
    srtp_aes_kw_key_ct_20_256,    /* ciphertext  + tag        */
    0,                            /* octets in AAD            */
    NULL,                         /* AAD                      */
    0,                            /* octets in tag            */
    &srtp_aes_kw_test_case_256_16 /* pointer to next testcase */
};

/*
 * This is the function table for this crypto engine.
 */
const srtp_cipher_type_t srtp_aes_kw_128 = {
    srtp_aes_kw_alloc,
    srtp_aes_kw_dealloc,
    srtp_aes_kw_context_init,
    0, /* set_aad */
    srtp_aes_kw_encrypt,
    srtp_aes_kw_decrypt,
    0, /* set_iv */
    0, /* get_tag */
    srtp_aes_kw_128_description,
    &srtp_aes_kw_test_case_128_20,
    SRTP_AES_KW_128,
};

const srtp_cipher_type_t srtp_aes_kw_256 = {
    srtp_aes_kw_alloc,
    srtp_aes_kw_dealloc,
    srtp_aes_kw_context_init,
    0, /* set_aad */
    srtp_aes_kw_encrypt,
    srtp_aes_kw_decrypt,
    0, /* set_iv */
    0, /* get_tag */
    srtp_aes_kw_256_description,
    &srtp_aes_kw_test_case_256_20,
    SRTP_AES_KW_256,
};
