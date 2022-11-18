#include <stdbool.h>

#include <wolfssl/ssl.h>
#include <wolfssl/openssl/bn.h>
#include <wolfssl/openssl/dh.h>
#include <wolfssl/openssl/evp.h>

bool DH_key_gen_init() { return wolfSSL_library_init() == SSL_SUCCESS; }

void *
DH_key_gen_new_from_params(const unsigned char *p, const unsigned char g, long pub_length, long priv_length) {
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

  if (priv_length && !wolfSSL_DH_set_length(dh, priv_length))
    goto fail;

  return dh;

fail:
  wolfSSL_DH_free(dh);
  wolfSSL_BN_clear_free(bn_p);
  wolfSSL_BN_clear_free(bn_g);

  return NULL;
}

void *
DH_key_gen_new_from_file(const char *dh_param_file_path, long priv_length) {
  FILE *dh_param_file;
  static unsigned char dh_param_file_content[16 * 1024];
  DerBuffer *der_buffer;
  WOLFSSL_DH *dh;

  dh_param_file = fopen(dh_param_file_path, "r");
  if (dh_param_file == NULL)
    goto fail;

  fseek(dh_param_file, 0, SEEK_END);
  unsigned long dh_param_file_size = ftell(dh_param_file);
  if (dh_param_file_size > sizeof(dh_param_file_content) / sizeof(*dh_param_file_content))
    goto fail;

  fseek(dh_param_file, 0, SEEK_SET);
  fread(&dh_param_file_content, dh_param_file_size, 1, dh_param_file);
  fclose(dh_param_file);

  int dh_param_der_size = wc_PemToDer(
    dh_param_file_content,
    sizeof(dh_param_file_content) / sizeof(*dh_param_file_content),
    DH_PARAM_TYPE,
    &der_buffer,
    NULL,
    NULL,
    NULL
  );
  if (dh_param_der_size < 0)
    goto fail;

  dh = wolfSSL_d2i_DHparams(&dh, (const unsigned char **)&der_buffer->buffer, der_buffer->length);
  if (dh == NULL)
    goto fail;

  if (priv_length && !wolfSSL_DH_set_length(dh, priv_length))
    goto fail;

  return dh;

fail:
  wolfSSL_DH_free(dh);

  return NULL;
}

void
DH_key_gen_free(void *_dh) {
  WOLFSSL_DH *dh = (WOLFSSL_DH *) _dh;

  wolfSSL_DH_free(dh);
}

int
DH_key_gen_generate_public_key(void *_dh) {
  WOLFSSL_DH *dh = (WOLFSSL_DH *) _dh;

  if (wolfSSL_DH_generate_key(dh) == 0)
    return -1;

  return wolfSSL_BN_num_bits(dh->priv_key);
}

int
DH_key_gen_get_length(void *_dh) {
  WOLFSSL_DH *dh = (WOLFSSL_DH *) _dh;

  return wolfSSL_BN_num_bits(dh->priv_key);
}
