#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>
#include <nettle/bignum.h>
#include <gmp.h>

#define GNUTLS_MAX_PK_PARAMS 16
#define MAX_PVP_SEED_SIZE 256

typedef void *bigint_t;

int _gnutls_mpi_init_scan_nz(bigint_t * ret_mpi, const void *buffer,
			size_t nbytes);

typedef enum {
	GNUTLS_IMPORT = 0,
	GNUTLS_EXPORT = 1
} gnutls_direction_t;

#define DH_P 0
#define DH_Q 1
#define DH_G 2
#define DH_Y 3
#define DH_X 4

typedef struct gnutls_x509_spki_st {
	/* We can have a key which is of type RSA, but a certificate
	 * of type RSA-PSS; the value here will be the expected value
	 * for signatures (i.e., RSA-PSS) */
	gnutls_pk_algorithm_t pk;

	/* the digest used by RSA-PSS */
	gnutls_digest_algorithm_t rsa_pss_dig;

	/* the size of salt used by RSA-PSS */
	unsigned int salt_size;

	/* if non-zero, the legacy value for PKCS#7 signatures will be
	 * written for RSA signatures. */
	unsigned int legacy;

	/* the digest used by ECDSA/DSA */
	gnutls_digest_algorithm_t dsa_dig;

	/* flags may include GNUTLS_PK_FLAG_REPRODUCIBLE for
	 * deterministic ECDSA/DSA */
	unsigned int flags;
} gnutls_x509_spki_st;

typedef struct {
	bigint_t params[GNUTLS_MAX_PK_PARAMS];
	unsigned int params_nr;	/* the number of parameters */
	unsigned int pkflags; /* gnutls_pk_flag_t */
	unsigned int qbits; /* GNUTLS_PK_DH */
	gnutls_ecc_curve_t curve; /* GNUTLS_PK_EC, GNUTLS_PK_ED25519, GNUTLS_PK_GOST* */
	gnutls_group_t dh_group; /* GNUTLS_PK_DH - used by ext/key_share */
	gnutls_gost_paramset_t gost_params; /* GNUTLS_PK_GOST_* */
	gnutls_datum_t raw_pub; /* used by x25519 */
	gnutls_datum_t raw_priv;

	unsigned int seed_size;
	uint8_t seed[MAX_PVP_SEED_SIZE];
	gnutls_digest_algorithm_t palgo;
	/* public key information */
	gnutls_x509_spki_st spki;

	gnutls_pk_algorithm_t algo;
} gnutls_pk_params_st;

/* Public key algorithms */
typedef struct gnutls_crypto_pk {
	/* The params structure should contain the private or public key
	 * parameters, depending on the operation */
	int (*encrypt) (gnutls_pk_algorithm_t, gnutls_datum_t * ciphertext,
			const gnutls_datum_t * plaintext,
			const gnutls_pk_params_st * pub);
	int (*decrypt) (gnutls_pk_algorithm_t,
                        gnutls_datum_t * plaintext,
			const gnutls_datum_t * ciphertext,
			const gnutls_pk_params_st * priv);
	int (*decrypt2) (gnutls_pk_algorithm_t,
			 const gnutls_datum_t * ciphertext,
                         unsigned char * plaintext,
                         size_t paintext_size,
			 const gnutls_pk_params_st * priv);
	int (*sign) (gnutls_pk_algorithm_t, gnutls_datum_t * signature,
		     const gnutls_datum_t * data,
		     const gnutls_pk_params_st *priv,
		     const gnutls_x509_spki_st *sign);
	int (*verify) (gnutls_pk_algorithm_t, const gnutls_datum_t * data,
		       const gnutls_datum_t * sig,
		       const gnutls_pk_params_st *pub,
		       const gnutls_x509_spki_st *sign);
	/* sanity checks the public key parameters */
	int (*verify_priv_params) (gnutls_pk_algorithm_t,
			      const gnutls_pk_params_st * priv);
	int (*verify_pub_params) (gnutls_pk_algorithm_t,
			      const gnutls_pk_params_st * pub);
	int (*generate_keys) (gnutls_pk_algorithm_t, unsigned int nbits,
			 gnutls_pk_params_st *, unsigned ephemeral);
	int (*generate_params) (gnutls_pk_algorithm_t, unsigned int nbits,
			 gnutls_pk_params_st *);
	/* this function should convert params to ones suitable
	 * for the above functions
	 */
	int (*pk_fixup_private_params) (gnutls_pk_algorithm_t,
					gnutls_direction_t,
					gnutls_pk_params_st *);
#define PK_DERIVE_TLS13 1
	int (*derive) (gnutls_pk_algorithm_t, gnutls_datum_t * out,
		       const gnutls_pk_params_st * priv,
		       const gnutls_pk_params_st * pub,
		       const gnutls_datum_t *nonce,
		       unsigned int flags);

	int (*curve_exists) (gnutls_ecc_curve_t);	/* true/false */
	int (*pk_exists) (gnutls_pk_algorithm_t);	/* true/false */
	int (*sign_exists) (gnutls_sign_algorithm_t);	/* true/false */
} gnutls_crypto_pk_st;

extern gnutls_crypto_pk_st _gnutls_pk_ops;

bool DH_key_gen_init() { return true; }

void *DH_key_gen_new_from_file(const char *dh_param_file_path, long priv_length) {
  FILE *dh_param_file;
  static unsigned char dh_param_file_content[16 * 1024];

  dh_param_file = fopen(dh_param_file_path, "r");
  if (dh_param_file == NULL)
    goto fail;

  fseek(dh_param_file, 0, SEEK_END);
  unsigned long dh_param_file_size = ftell(dh_param_file);
  if (dh_param_file_size > sizeof(dh_param_file_content) / sizeof(*dh_param_file_content))
    goto fail;

  fseek(dh_param_file, 0, SEEK_SET);
  fread(dh_param_file_content, dh_param_file_size, 1, dh_param_file);
  fclose(dh_param_file);

  gnutls_datum_t dh_param = { dh_param_file_content, dh_param_file_size };
  gnutls_dh_params_t dh = NULL;
  if (gnutls_dh_params_init(&dh) != 0)
    goto fail;

  if (gnutls_dh_params_import_pkcs3(dh, &dh_param, GNUTLS_X509_FMT_PEM) < 0)
    goto fail;

  gnutls_datum_t p, g;
  unsigned int bits;

  if (gnutls_dh_params_export_raw(dh, &p, &g, &bits))
    goto fail;

  if (gnutls_dh_params_init(&dh) != 0)
    goto fail;

  if (gnutls_dh_params_import_raw2(dh, &p, &g, priv_length ? priv_length : bits) != 0)
    goto fail;

  return dh;

fail:
  if (dh_param_file)
    fclose(dh_param_file);

  gnutls_dh_params_deinit(dh);

  return NULL;
}

void *
DH_key_gen_new_from_params(const unsigned char *p, const unsigned char g, long pub_length, long priv_length) {
  gnutls_dh_params_t dh = NULL;
  const gnutls_datum_t datum_p = { .data = (void *) p, .size = pub_length / 8 };
  const gnutls_datum_t datum_g = { .data = (void *) &g, .size = 1 };

  if (gnutls_dh_params_init(&dh) != 0)
    goto fail;

  if (gnutls_dh_params_import_raw2(dh, &datum_p, &datum_g, priv_length) != 0)
    goto fail;

  return dh;

fail:
  gnutls_dh_params_deinit(dh);

  return NULL;
}

void
DH_key_gen_free(void *_dh) {
  gnutls_dh_params_t dh = (gnutls_dh_params_t) _dh;

  gnutls_dh_params_deinit(dh);
}

int
DH_key_gen_generate_public_key(void *_dh) {
  gnutls_dh_params_t dh = (gnutls_dh_params_t) _dh;
  gnutls_datum_t p, g;
  bigint_t tmp_p, tmp_g;
  unsigned int bits;
  gnutls_pk_params_st pk = {0};
  gnutls_datum_t priv_key = {0}, pub_key = {0};

  if (gnutls_dh_params_export_raw(dh, &p, &g, &bits))
    goto fail;

  pk.algo = GNUTLS_PK_DH;

  if (_gnutls_mpi_init_scan_nz(&tmp_p, p.data, p.size))
    goto fail;
  pk.params[DH_P] = tmp_p;
  if (_gnutls_mpi_init_scan_nz(&tmp_g, g.data, g.size))
    goto fail;
  pk.params[DH_G] = tmp_g;
  pk.params[DH_Q] = NULL;

  if (_gnutls_pk_ops.generate_keys(GNUTLS_PK_DH, bits, &pk, 1) < 0)
      goto fail;

  return nettle_mpz_sizeinbase_256_u(*(mpz_t *) pk.params[DH_X]) * 8;

fail:
  gnutls_dh_params_deinit(dh);
  gnutls_free(priv_key.data);
  gnutls_free(pub_key.data);

  return -1;
}

int
DH_key_gen_get_length(void *_dh) {
  gnutls_dh_params_t dh = (gnutls_dh_params_t) _dh;
  gnutls_datum_t p, g;
  unsigned int bits;

  if (gnutls_dh_params_export_raw(dh, &p, &g, &bits))
    return 0;

  return bits;
}
