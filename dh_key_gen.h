#ifndef GEN_DH_H
#define GEN_DH_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

bool DH_key_gen_init();
void *DH_key_gen_new_from_params(const unsigned char *p, const unsigned char g, long pub_length, long priv_length);
int DH_key_gen_generate_public_key(void *dh, long priv_length);
void DH_key_gen_free(void *dh);

#ifdef __cplusplus
}
#endif

#endif
