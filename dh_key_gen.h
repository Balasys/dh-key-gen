#ifndef GEN_DH_H
#define GEN_DH_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

void *DH_key_gen_new(const char *name, const unsigned char *p, const unsigned char g, long pub_length, long priv_length);
int DH_key_gen_generate_keypair(void *dh, long priv_length);
void DH_key_gen_free(void *dh);

#ifdef __cplusplus
}
#endif

#endif
