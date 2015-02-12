/**
 * A collection of exposed wrapper functions for Erlang
 * Author: David Ellefsen <davidellefsen@gmail.com>
 *
 * Copyright 2015 David Ellefsen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

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

