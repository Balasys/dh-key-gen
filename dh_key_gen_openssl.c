#include <stdbool.h>

#include "dh_key_gen_openssl.h"

#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/evp.h>


bool DH_key_gen_init()
{
  return true;
}

void *
DH_key_gen_new_from_params(const unsigned char *p, const unsigned char g, long pub_length, long priv_length) {
  DH *dh = NULL;
  BIGNUM *bn_p = NULL, *bn_g = NULL;

  if ((dh = DH_new()) == NULL)
    return NULL;

  if ((bn_p = BN_bin2bn(p, pub_length / 8, NULL)) == NULL)
    goto fail;

  if ((bn_g = BN_bin2bn(&g, 1, NULL)) == NULL)
    goto fail;

  DH_set0_pqg(dh, bn_p, NULL, bn_g);

  if (priv_length) {
    int p_bits = BN_num_bits(DH_get0_p(dh));
    DH_set_length(dh, priv_length < p_bits ? priv_length : p_bits - 1);
  }

  return dh;

fail:
  if (dh) {
    DH_free(dh);
  } else {
    BN_clear_free(bn_p);
    BN_clear_free(bn_g);
  }

  return NULL;
}

void
DH_key_gen_free(void *_dh) {
  DH *dh = (DH *) _dh;

  DH_free(dh);
}

int
DH_key_gen_generate_public_key(void *_dh) {
  DH *dh = (DH *) _dh;

  if (DH_generate_key(dh) == 0)
    return -1;

  const BIGNUM *priv_key = DH_get0_priv_key(dh);

  return BN_num_bits(priv_key);
}
