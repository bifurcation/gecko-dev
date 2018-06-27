/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

// Original author: ekr@rtfm.com

#include "logging.h"
#include "SrtpFlow.h"

#include "srtp.h"
#include "ekt.h"
#include "ssl.h"
#include "sslproto.h"

#include "mozilla/RefPtr.h"

static const char* sfLogTag = "SrtpFlow";
#ifdef LOGTAG
#undef LOGTAG
#endif
#define LOGTAG sfLogTag

using namespace mozilla;

namespace mozilla {

bool SrtpFlow::initialized;  // Static

SrtpFlow::~SrtpFlow() {
  if (session_) {
    srtp_dealloc(session_);
  }
  if(ekt_) {
    ekt_dealloc(ekt_);
  }
}

unsigned int SrtpFlow::KeySize(int cipher_suite) {
  srtp_profile_t profile = static_cast<srtp_profile_t>(cipher_suite);
  return srtp_profile_get_master_key_length(profile);
}

unsigned int SrtpFlow::SaltSize(int cipher_suite) {
  srtp_profile_t profile = static_cast<srtp_profile_t>(cipher_suite);
  return srtp_profile_get_master_salt_length(profile);
}

RefPtr<SrtpFlow> SrtpFlow::Create(int cipher_suite,
                                           bool inbound,
                                           const void *key,
                                           size_t key_len,
                                           int ekt_cipher_suite,
                                           void* ssl_ekt_key) {
  nsresult res = Init();
  if (!NS_SUCCEEDED(res))
    return nullptr;

  RefPtr<SrtpFlow> flow = new SrtpFlow();

  if (!key) {
    CSFLogError(LOGTAG, "Null SRTP key specified");
    return nullptr;
  }

  srtp_policy_t policy;
  memset(&policy, 0, sizeof(srtp_policy_t));

  // In DTLS-SRTP, the protection profile negotiated by the DTLS
  // handshake determines the ciphers to be used for RTP and RTCP.
  srtp_profile_t profile = static_cast<srtp_profile_t>(cipher_suite);

  srtp_err_status_t r;
  r = srtp_crypto_policy_set_from_profile_for_rtp(&policy.rtp, profile);
  if (r != srtp_err_status_ok) {
    CSFLogError(LOGTAG, "Error creating srtp session");
    return nullptr;
  }

  r = srtp_crypto_policy_set_from_profile_for_rtcp(&policy.rtcp, profile);
  if (r != srtp_err_status_ok) {
    CSFLogError(LOGTAG, "Error creating srtp session");
    return nullptr;
  }

  // This key is copied into the srtp_t object, so we don't
  // need to keep it.
  policy.key = const_cast<unsigned char *>(
      static_cast<const unsigned char *>(key));
  policy.ssrc.type = inbound ? ssrc_any_inbound : ssrc_any_outbound;
  policy.ssrc.value = 0;
  policy.window_size = 1024;   // Use the Chrome value.  Needs to be revisited.  Default is 128
  policy.allow_repeat_tx = 1;  // Use Chrome value; needed for NACK mode to work
  policy.next = nullptr;

  // Now make the session
  r = srtp_create(&flow->session_, &policy);
  if (r != srtp_err_status_ok) {
    CSFLogError(LOGTAG, "Error creating srtp session");
    return nullptr;
  }

  if (ssl_ekt_key != nullptr) {
    // setup ekt context
    SSLEKTKey *ekt_key_info = static_cast<SSLEKTKey *>(ssl_ekt_key);
    r = ekt_create(&flow->ekt_, ekt_key_info->ektSPI, ekt_cipher_suite, ekt_key_info->ektKeyValue, 
                   ekt_key_info->ektKeyLength);
  
    if (r != srtp_err_status_ok) {
      CSFLogError(LOGTAG, "Error creating ekt context");
      return nullptr;
    }
  } 

  return flow;
}


nsresult SrtpFlow::CheckInputs(bool protect, void *in, int in_len,
                               int max_len, int *out_len) {
  MOZ_ASSERT(in);
  if (!in) {
    CSFLogError(LOGTAG, "NULL input value");
    return NS_ERROR_NULL_POINTER;
  }

  if (in_len < 0) {
    CSFLogError(LOGTAG, "Input length is negative");
    return NS_ERROR_ILLEGAL_VALUE;
  }

  if (max_len < 0) {
    CSFLogError(LOGTAG, "Max output length is negative");
    return NS_ERROR_ILLEGAL_VALUE;
  }

  if (protect) {
    if ((max_len < SRTP_MAX_EXPANSION) ||
        ((max_len - SRTP_MAX_EXPANSION) < in_len)) {
      CSFLogError(LOGTAG, "Output too short");
      return NS_ERROR_ILLEGAL_VALUE;
    }
  }
  else {
    if (in_len > max_len) {
      CSFLogError(LOGTAG, "Output too short");
      return NS_ERROR_ILLEGAL_VALUE;
    }
  }

  return NS_OK;
}

nsresult SrtpFlow::ProtectRtp(void *in, int in_len,
                              int max_len, int *out_len) {
  nsresult res = CheckInputs(true, in, in_len, max_len, out_len);
  if (NS_FAILED(res))
    return res;

  int len = in_len;
  srtp_err_status_t r = srtp_protect(session_, in, &len);

  if (r != srtp_err_status_ok) {
    CSFLogError(LOGTAG, "Error protecting SRTP packet");
    return NS_ERROR_FAILURE;
  }

  if (ekt_) {
    // add the half ekt tag
    r = ekt_add_tag(ekt_, session_, static_cast<uint8_t *>(in), &len, EKT_FLAG_HALF_KEY);
  }

  if (r != srtp_err_status_ok) {
    CSFLogError(LOGTAG, "Error adding SRTP EKT tag to the packet=%d", (int)r);
    return NS_ERROR_FAILURE;
  }

  MOZ_ASSERT(len <= max_len);
  *out_len = len;

  CSFLogDebug(LOGTAG, "Successfully protected an SRTP packet of len %d",
              *out_len);

  return NS_OK;
}

nsresult SrtpFlow::UnprotectRtp(void *in, int in_len,
                                int max_len, int *out_len) {
  nsresult res = CheckInputs(false, in, in_len, max_len, out_len);
  if (NS_FAILED(res))
    return res;

  srtp_err_status_t r;
  int len = in_len;
  if (ekt_) {
    r = ekt_process_tag(ekt_, session_, static_cast<uint8_t *>(in), &len);
    if (r != srtp_err_status_ok) {
      CSFLogError(LOGTAG, "Error processing SRTP EKT Tag=%d", (int)r);
      return NS_ERROR_FAILURE;
    }
    MOZ_ASSERT(len <= max_len);
  }

  r = srtp_unprotect(session_, in, &len);

  if (r != srtp_err_status_ok) {
    CSFLogError(LOGTAG, "Error unprotecting SRTP packet error=%d", (int)r);
    return NS_ERROR_FAILURE;
  }

  MOZ_ASSERT(len <= max_len);
  *out_len = len;

  CSFLogDebug(LOGTAG, "Successfully unprotected an SRTP packet of len %d",
              *out_len);

  return NS_OK;
}

nsresult SrtpFlow::ProtectRtcp(void *in, int in_len,
                               int max_len, int *out_len) {
  nsresult res = CheckInputs(true, in, in_len, max_len, out_len);
  if (NS_FAILED(res))
    return res;

  int len = in_len;
  srtp_err_status_t r = srtp_protect_rtcp(session_, in, &len);

  if (r != srtp_err_status_ok) {
    CSFLogError(LOGTAG, "Error protecting SRTCP packet");
    return NS_ERROR_FAILURE;
  }

  MOZ_ASSERT(len <= max_len);
  *out_len = len;

  CSFLogDebug(LOGTAG, "Successfully protected an SRTCP packet of len %d",
              *out_len);

  return NS_OK;
}

nsresult SrtpFlow::UnprotectRtcp(void *in, int in_len,
                                 int max_len, int *out_len) {
  nsresult res = CheckInputs(false, in, in_len, max_len, out_len);
  if (NS_FAILED(res))
    return res;

  int len = in_len;
  srtp_err_status_t r = srtp_unprotect_rtcp(session_, in, &len);

  if (r != srtp_err_status_ok) {
    CSFLogError(LOGTAG, "Error unprotecting SRTCP packet error=%d", (int)r);
    return NS_ERROR_FAILURE;
  }

  MOZ_ASSERT(len <= max_len);
  *out_len = len;

  CSFLogDebug(LOGTAG, "Successfully unprotected an SRTCP packet of len %d",
              *out_len);

  return NS_OK;
}

// Statics
void SrtpFlow::srtp_event_handler(srtp_event_data_t *data) {
  // TODO(ekr@rtfm.com): Implement this
  MOZ_CRASH();
}

nsresult SrtpFlow::Init() {
  if (!initialized) {
    srtp_err_status_t r = srtp_init();
    if (r != srtp_err_status_ok) {
      CSFLogError(LOGTAG, "Could not initialize SRTP");
      MOZ_ASSERT(PR_FALSE);
      return NS_ERROR_FAILURE;
    }

    r = srtp_install_event_handler(&SrtpFlow::srtp_event_handler);
    if (r != srtp_err_status_ok) {
      CSFLogError(LOGTAG, "Could not install SRTP event handler");
      MOZ_ASSERT(PR_FALSE);
      return NS_ERROR_FAILURE;
    }

    initialized = true;
  }

  return NS_OK;
}

}  // end of namespace

