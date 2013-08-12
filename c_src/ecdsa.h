#ifndef ECDSA_H
#define ECDSA_H

#include "erl_nif.h"

ERL_NIF_TERM ecdsa_generate_public_key(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

#endif
