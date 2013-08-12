#ifndef HMAC_H
#define HMAC_H

#include "erl_nif.h"

ERL_NIF_TERM hmac_sha512(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

#endif
