#include <getopt.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dh_key_gen.h"
#include "dh_params.h"


void
handle_argument_error(const char *arg_name)
{
  if (arg_name)
    fprintf(stderr, "Wrong value for %s. ", arg_name);

  fprintf(stderr, "%s\n",
    "Usage: dh_key_gen_lib_postfix "
    "--param-type {ffdhe,modp} "
    "--param-size public-key-length-in-bits "
    "--priv-key-size private-key-length-in-bits "
    "--count number-of-dh-key-generations "
    "[--log]"
  );

  exit(1);
}


int
main (int argc, char **argv)
{
  int option_index = 0;
  static int log_flag = 0;
  const char *param_type = NULL;
  long param_size = 0, priv_key_size = 0, count = 0;

  while (true)
    {
      static struct option long_options[] =
        {
          {"log",            no_argument,       &log_flag, 1},
          {"param-type",     required_argument, 0,         't'},
          {"param-size",     required_argument, 0,         's'},
          {"priv-key-size",  required_argument, 0,         'p'},
          {"count",          required_argument, 0,         'c'},
          {0, 0, 0, 0}
        };
      int c = getopt_long (argc, argv, "t:s:p:c", long_options, &option_index);

      if (c == -1)
        break;

      switch (c)
        {
        case 0:
          break;

        case 't':
          param_type = optarg;
          break;

        case 's':
          param_size = atol(optarg);
          break;

        case 'p':
          priv_key_size = atol(optarg);
          break;

        case 'c':
          count = atol(optarg);
          break;

        case '?':
          handle_argument_error(NULL);
          break;

        default:
          abort ();
        }
    }

  if (param_type == NULL)
    handle_argument_error("param-type");
  if (param_size == 0)
    handle_argument_error("param-size");
  if (count == 0)
    handle_argument_error("count");

  char *dhparam_name[11];
  snprintf((char *) dhparam_name, sizeof(dhparam_name), "%s%ld", param_type, param_size);

  const dhparam *chosen_dhparam = NULL;
  for (int i = 0; dhparams[i].name != NULL; i++) {
    if (strcmp(dhparams[i].name, (char *)dhparam_name) == 0) {
      chosen_dhparam = &dhparams[i];
      break;
    }
  }

  if (chosen_dhparam == NULL)
    handle_argument_error("param-type or param-size");

  if (log_flag)
    fprintf(stderr, "Generating DH public key %ld time(s) using public parameters %s", count, chosen_dhparam->name);

  if (!DH_key_gen_init()) {
    if (log_flag)
      fprintf(stderr, "\nCryptographic library initialization error\n");

    return 1;
  }

  double total_time = 0.0;
  for (long i = 0; i < count; i++) {
    void *dh = DH_key_gen_new_from_params(chosen_dhparam->p, chosen_dhparam->g, chosen_dhparam->size, priv_key_size);

    const clock_t start_time = clock();
    int priv_key_size_actual = DH_key_gen_generate_public_key(dh, priv_key_size);
    const clock_t end_time = clock();
    total_time += ((double) (end_time - start_time)) / CLOCKS_PER_SEC;

    if (priv_key_size_actual < 0) {
      if (log_flag)
        fprintf(stderr, "\nDH public key generation error\n");

      return 1;
    } else if (log_flag && (i == 0)) {
      fprintf(stderr, " with %d bit private keys\n", priv_key_size_actual);
    }

    DH_key_gen_free(dh);
  }

  printf("Key generation speed: %12.6f ops/s\n", count / total_time);

  return 0;
}
