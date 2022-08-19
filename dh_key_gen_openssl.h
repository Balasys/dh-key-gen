#ifndef GEN_DH_OPENSSL_H
#define GEN_DH_OPENSSL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/opensslv.h>

#if defined OPENSSL_VERSION_NUMBER && OPENSSL_VERSION_NUMBER < 0x10100000L
#include <crypto/dh/dh.h>
#define DH_get0_p(dh) dh->p
#define DH_get0_pub_key(dh) dh->pub_key
#define DH_get0_priv_key(dh) dh->priv_key

static inline int DH_set_length(DH *dh, long length) { dh->length = length; return 0; }
static inline int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g) { dh->p = p; dh->q = q; dh->g = g; return 0; }
#endif

#ifdef __cplusplus
}
#endif

#endif
