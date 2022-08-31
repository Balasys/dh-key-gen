#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/dhm.h>
#include <mbedtls/bignum.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>


void *
DH_key_gen_new(const char *name, const unsigned char *p, const unsigned char g, long pub_length, long priv_length) {
  mbedtls_dhm_context *dh;
  mbedtls_mpi mpi_p, mpi_g;

  dh = malloc(sizeof(mbedtls_dhm_context));
  if (dh == NULL)
    goto fail;

  mbedtls_dhm_init(dh);
  mbedtls_mpi_init(&mpi_p);
  mbedtls_mpi_init(&mpi_g);

  if (mbedtls_mpi_read_binary(&mpi_p, p, pub_length / 8) != 0)
    goto fail;
  if (mbedtls_mpi_read_binary(&mpi_g, &g, 1) != 0)
    goto fail;

  if (mbedtls_dhm_set_group(dh, &mpi_p, &mpi_g) != 0)
    goto fail;

  return dh;

fail:
  mbedtls_mpi_free(&mpi_p);
  mbedtls_mpi_free(&mpi_g);
  mbedtls_dhm_free(dh);
  free(dh);

  return NULL;
}

void
DH_key_gen_free(void *_dh) {
  mbedtls_dhm_context *dh = (mbedtls_dhm_context *) _dh;

  mbedtls_dhm_free(dh);
  free(dh);
}

int
DH_key_gen_generate_keypair(void *_dh, long priv_key_size) {
  mbedtls_dhm_context *dh = (mbedtls_dhm_context *) _dh;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  unsigned char buf[2048];
  const char *pers = "dh_server";
  size_t n;

  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init(&entropy);
  if(mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                             (const unsigned char *) pers,
                             strlen(pers)) != 0 )
    return -1;

  memset(buf, 0, sizeof(buf));
  if (mbedtls_dhm_make_params(dh, priv_key_size / 8, buf, &n, mbedtls_ctr_drbg_random, &ctr_drbg) != 0)
    return -1;

  return mbedtls_mpi_size(&dh->X) * 8;
}
