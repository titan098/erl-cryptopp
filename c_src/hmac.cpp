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
