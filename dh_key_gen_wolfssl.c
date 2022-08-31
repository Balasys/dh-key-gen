#include <stdbool.h>

#include <wolfssl/ssl.h>
#include <wolfssl/openssl/bn.h>
#include <wolfssl/openssl/dh.h>
#include <wolfssl/openssl/evp.h>

void *
DH_key_gen_new(const char *name, const unsigned char *p, const unsigned char g, long pub_length, long priv_length) {
  WOLFSSL_DH *dh;
  WOLFSSL_BIGNUM *bn_p = NULL, *bn_g = NULL;

  if ((dh = wolfSSL_DH_new()) == NULL)
    return NULL;

  if ((bn_p = wolfSSL_BN_bin2bn(p, pub_length / 8, NULL)) == NULL)
    goto fail;

  if ((bn_g = wolfSSL_BN_bin2bn(&g, 1, NULL)) == NULL)
    goto fail;

  if (wolfSSL_DH_set0_pqg(dh, bn_p, NULL, bn_g) == 0)
    goto fail;

  if (priv_length) {
    int p_bits = wolfSSL_BN_num_bits(bn_p);
    if (wolfSSL_DH_set_length(dh, priv_length) == 0)
      goto fail;
  }

  return dh;

fail:
  wolfSSL_DH_free(dh);
  wolfSSL_BN_clear_free(bn_p);
  wolfSSL_BN_clear_free(bn_g);

  return NULL;
}

void
DH_key_gen_free(void *_dh) {
  WOLFSSL_DH *dh = (WOLFSSL_DH *) _dh;

  wolfSSL_DH_free(dh);
}

int
DH_key_gen_generate_keypair(void *_dh) {
  WOLFSSL_DH *dh = (WOLFSSL_DH *) _dh;

  static char key[8192];
  const WOLFSSL_BIGNUM *priv_key;

  if (wolfSSL_DH_generate_key(dh) == 0)
    return -1;

  return wolfSSL_BN_num_bits(dh->priv_key);
}

int
DH_key_gen_get_length(void *_dh) {
  WOLFSSL_DH *dh = (WOLFSSL_DH *) _dh;

  return wolfSSL_BN_num_bits(dh->priv_key);
}
