#ifndef GEN_DH_PARAMS_H
#define GEN_DH_PARAMS_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dhparam_t {
  const char *name;
  const long size;
  const unsigned char *p;
  const unsigned char g;
} dhparam;

extern const dhparam *dhparams;

#ifdef __cplusplus
}
#endif

#endif
