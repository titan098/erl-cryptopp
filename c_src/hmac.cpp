/**
 * A collection of HMAC wrapper functions for Erlang
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

#include "hmac.h"

#include <cryptlib.h>
#include <hmac.h>
#include <sha.h>

using namespace CryptoPP;

void calculate_hmac(ErlNifEnv* env, MessageAuthenticationCode* c, ErlNifBinary* inBin, ERL_NIF_TERM* outBin) {
	int size = c->DigestSize();
	byte digest[size];
	c->CalculateDigest(digest, inBin->data, inBin->size);
	
	//copy the output to the term
	byte* q = (byte*)enif_make_new_binary(env, size, outBin);
	memcpy(q, digest, size);
	memset(digest, 0x00, size);
}

ERL_NIF_TERM hmac_sha512(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
	//get the buffer
	ErlNifBinary key, data;
	ERL_NIF_TERM r;

	if (!enif_inspect_binary(env, argv[0], &key)) {
		return enif_make_badarg(env);
	}

	if (!enif_inspect_binary(env, argv[1], &data)) {
		return enif_make_badarg(env);
	}

	//the buffer shouldn't be modified by the SHA functions, but you never know
	// for now I won't make a copy, but if funny things happen, then I will have to.	
	HMAC<SHA512> c(key.data, key.size);
	calculate_hmac(env, &c, &data, &r);	

	return r;
}
