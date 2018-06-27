/*
 * ekt.h
 *
 * interface to EKT functions of libsrtp
 *
 * Richard L. Barnes
 * Cisco Systems, Inc.
 */
/*
 *
 * Copyright (c) 2001-2017, Cisco Systems, Inc.
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
#ifndef EKT_EKT_H
#define EKT_EKT_H

#include "srtp.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint16_t ekt_spi_t;

typedef uint8_t ekt_cipher_t;
#define EKT_CIPHER_AESKW_128 0x01
#define EKT_CIPHER_AESKW_256 0x02

typedef uint32_t ekt_flags_t;
#define EKT_FLAG_SHORT_TAG 0x00000001

#define MAX_EKT_KEY_LEN 32

typedef struct ekt_ctx_t_ ekt_ctx_t;
typedef ekt_ctx_t *ekt_t;

/*
 * Allocate and initialize an EKT context, which can then be used
 * to create and process tags.
 */
/* TODO-RLB: All of these arguments can be marked const */
srtp_err_status_t
ekt_create(ekt_t *ctx, ekt_spi_t spi, ekt_cipher_t cipher, uint8_t *key, size_t key_size);

/*
 * Deallocate an EKT context
 */
srtp_err_status_t
ekt_dealloc(ekt_t ctx);

/*
 * Append an EKT tag to an encrypted packet
 */
/* TODO-RLB: Some of these arguments can be marked const */
srtp_err_status_t
ekt_add_tag(ekt_t ctx, srtp_t session, uint8_t *pkt, int *pkt_size, ekt_flags_t flags);

/*
 * Parse an EKT tag from an encrypted packet and update the session
 * as appropriate
 */
/* TODO-RLB: Some of these arguments can be marked const */
srtp_err_status_t
ekt_process_tag(ekt_t ctx, srtp_t session, uint8_t *pkt, int *pkt_size);

#ifdef __cplusplus
}
#endif

#endif /* EKT_EKT_H */
