#include "hash.h"
#include "hmac.h"
#include "ecdsa.h"

static ErlNifFunc nif_funcs[] = {
	{"nif_hash_sha1",	1, hash_sha1},
	{"nif_hash_sha224",	1, hash_sha224},
	{"nif_hash_sha256",	1, hash_sha256},
	{"nif_hash_sha384",	1, hash_sha384},
	{"nif_hash_sha512",	1, hash_sha512},
	{"nif_hash_sha3_224",	1, hash_sha3_224},
	{"nif_hash_sha3_256",	1, hash_sha3_256},
	{"nif_hash_sha3_384",	1, hash_sha3_384},
	{"nif_hash_sha3_512",	1, hash_sha3_512},
	{"nif_hash_ripemd128",	1, hash_ripemd128},
	{"nif_hash_ripemd160",	1, hash_ripemd160},
	{"nif_hash_ripemd256",	1, hash_ripemd256},
	{"nif_hash_ripemd320",	1, hash_ripemd320},
	{"nif_hash_tiger",	1, hash_tiger},
	{"nif_hash_whirlpool",	1, hash_whirlpool},
	{"nif_hash_md2",	1, hash_md2},
	{"nif_hash_md4",	1, hash_md4},
	{"nif_hash_md5",	1, hash_md5},

	{"nif_hmac_sha512",	2, hmac_sha512},

	{"nif_ecdsa_generate_public_key", 2, ecdsa_generate_public_key},
	{"nif_ecdsa_generate_private_key", 1, ecdsa_generate_private_key},
	{"nif_ecdsa_get_modulus", 1, ecdsa_get_modulus},
	{"nif_ecdsa_point_addition", 3, ecdsa_point_addition},
	{"nif_ecdsa_point_multiplication", 3, ecdsa_point_multiplication},
	{"nif_ecdsa_decode_point", 2, ecdsa_decode_point},
	{"nif_ecdsa_get_base_point", 1, ecdsa_get_base_point},

	{"nif_ecdsa_sign", 3, ecdsa_sign},
	{"nif_ecdsa_verify", 4, ecdsa_verify}
};

ERL_NIF_INIT(cryptopp, nif_funcs, NULL, NULL, NULL, NULL)

