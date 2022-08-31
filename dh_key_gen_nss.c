#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <nss/nss.h>
#include <nss/blapit.h>
#include <nss/secerr.h>
#include <nss/secitem.h>

extern SECStatus DH_NewKey(DHParams *params,
                           DHPrivateKey **privKey);

extern SECStatus DH_Derive(SECItem *publicValue,
                           SECItem *prime,
                           SECItem *privateValue,
                           SECItem *derivedSecret,
                           unsigned int outBytes);

void *
DH_key_gen_new(const char *name, const unsigned char *p, const unsigned char g, long pub_length, long priv_length) {
  DHParams *dh_params;

  if (!NSS_IsInitialized() && NSS_NoDB_Init(NULL) < 0)
      return NULL;

  dh_params = malloc(sizeof(DHParams));
  if (dh_params == NULL)
    goto fail;

  memset(dh_params, 0, sizeof(DHParams));

  dh_params->prime.data = malloc(pub_length / 8);
  memcpy(dh_params->prime.data, p, pub_length / 8);
  dh_params->prime.len = pub_length / 8;
  dh_params->base.data = malloc(1);
  memcpy(dh_params->base.data, &g, 1);
  dh_params->base.len = 1;

  return dh_params;

fail:
  free(dh_params);

  return NULL;
}

void
DH_key_gen_free(void *_dh) {
  DHParams *dh_params = (DHParams *) _dh;

  free(dh_params);
}

int
DH_key_gen_generate_keypair(void *_dh, long priv_length) {
  DHParams *dh_params = (DHParams *) _dh;
  DHPrivateKey *dh_privkey = NULL;
  SECItem secret;

  if (DH_NewKey(dh_params, &dh_privkey) != SECSuccess)
    return -1;

  return dh_privkey->privateValue.len * 8;
}
