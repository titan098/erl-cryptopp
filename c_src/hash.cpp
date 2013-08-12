#include "hash.h"

#include <cryptlib.h>
#include <sha.h>
#include <sha3.h>
#include <ripemd.h>
#include <tiger.h>
#include <whrlpool.h>

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <md2.h>
#include <md4.h>
#include <md5.h>

using namespace CryptoPP;

void calculate_digest(ErlNifEnv* env, HashTransformation* c, ErlNifBinary* inBin, ERL_NIF_TERM* outBin) {
	int size = c->DigestSize();
	byte digest[size];
	c->CalculateDigest(digest, inBin->data, inBin->size);
	
	//copy the output to the term
	byte* q = (byte*)enif_make_new_binary(env, size, outBin);
	memcpy(q, digest, size);
}

ERL_NIF_TERM hash_sha1(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
	//get the buffer
	ErlNifBinary p;
	ERL_NIF_TERM r;

	if (!enif_inspect_binary(env, argv[0], &p)) {
		return enif_make_badarg(env);
	}

	//the buffer shouldn't be modified by the SHA functions, but you never know
	// for now I won't make a copy, but if funny things happen, then I will have to.	
	SHA1 c = SHA1();
	calculate_digest(env, &c, &p, &r);	

	return r;
}

ERL_NIF_TERM hash_sha224(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
	//get the buffer
	ErlNifBinary p;
	ERL_NIF_TERM r;

	if (!enif_inspect_binary(env, argv[0], &p)) {
		return enif_make_badarg(env);
	}

	//the buffer shouldn't be modified by the SHA functions, but you never know
	// for now I won't make a copy, but if funny things happen, then I will have to.	
	SHA224 c = SHA224();
	calculate_digest(env, &c, &p, &r);	

	return r;
}

ERL_NIF_TERM hash_sha256(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
	//get the buffer
	ErlNifBinary p;
	ERL_NIF_TERM r;

	if (!enif_inspect_binary(env, argv[0], &p)) {
		return enif_make_badarg(env);
	}

	//the buffer shouldn't be modified by the SHA functions, but you never know
	// for now I won't make a copy, but if funny things happen, then I will have to.	
	SHA256 c = SHA256();
	calculate_digest(env, &c, &p, &r);	

	return r;
}

ERL_NIF_TERM hash_sha384(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
	//get the buffer
	ErlNifBinary p;
	ERL_NIF_TERM r;

	if (!enif_inspect_binary(env, argv[0], &p)) {
		return enif_make_badarg(env);
	}

	//the buffer shouldn't be modified by the SHA functions, but you never know
	// for now I won't make a copy, but if funny things happen, then I will have to.	
	SHA384 c = SHA384();
	calculate_digest(env, &c, &p, &r);	

	return r;
}

ERL_NIF_TERM hash_sha512(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
	//get the buffer
	ErlNifBinary p;
	ERL_NIF_TERM r;

	if (!enif_inspect_binary(env, argv[0], &p)) {
		return enif_make_badarg(env);
	}

	//the buffer shouldn't be modified by the SHA functions, but you never know
	// for now I won't make a copy, but if funny things happen, then I will have to.	
	SHA512 c = SHA512();
	calculate_digest(env, &c, &p, &r);	

	return r;
}

ERL_NIF_TERM hash_sha3_224(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
	//get the buffer
	ErlNifBinary p;
	ERL_NIF_TERM r;

	if (!enif_inspect_binary(env, argv[0], &p)) {
		return enif_make_badarg(env);
	}
	//the buffer shouldn't be modified by the SHA functions, but you never know
	// for now I won't make a copy, but if funny things happen, then I will have to.	
	SHA3_224 c = SHA3_224();
	calculate_digest(env, &c, &p, &r);	

	return r;
}

ERL_NIF_TERM hash_sha3_256(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
	//get the buffer
	ErlNifBinary p;
	ERL_NIF_TERM r;

	if (!enif_inspect_binary(env, argv[0], &p)) {
		return enif_make_badarg(env);
	}

	//the buffer shouldn't be modified by the SHA functions, but you never know
	// for now I won't make a copy, but if funny things happen, then I will have to.	
	SHA3_256 c = SHA3_256();
	calculate_digest(env, &c, &p, &r);	

	return r;
}

ERL_NIF_TERM hash_sha3_384(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
	//get the buffer
	ErlNifBinary p;
	ERL_NIF_TERM r;

	if (!enif_inspect_binary(env, argv[0], &p)) {
		return enif_make_badarg(env);
	}

	//the buffer shouldn't be modified by the SHA functions, but you never know
	// for now I won't make a copy, but if funny things happen, then I will have to.	
	SHA3_384 c = SHA3_384();
	calculate_digest(env, &c, &p, &r);	

	return r;
}

ERL_NIF_TERM hash_sha3_512(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
	//get the buffer
	ErlNifBinary p;
	ERL_NIF_TERM r;

	if (!enif_inspect_binary(env, argv[0], &p)) {
		return enif_make_badarg(env);
	}

	//the buffer shouldn't be modified by the SHA functions, but you never know
	// for now I won't make a copy, but if funny things happen, then I will have to.	
	SHA3_512 c = SHA3_512();
	calculate_digest(env, &c, &p, &r);	

	return r;
}

ERL_NIF_TERM hash_ripemd128(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
	//get the buffer
	ErlNifBinary p;
	ERL_NIF_TERM r;

	if (!enif_inspect_binary(env, argv[0], &p)) {
		return enif_make_badarg(env);
	}

	//the buffer shouldn't be modified by the SHA functions, but you never know
	// for now I won't make a copy, but if funny things happen, then I will have to.	
	RIPEMD128 c = RIPEMD128();
	calculate_digest(env, &c, &p, &r);	

	return r;
}

ERL_NIF_TERM hash_ripemd160(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
	//get the buffer
	ErlNifBinary p;
	ERL_NIF_TERM r;

	if (!enif_inspect_binary(env, argv[0], &p)) {
		return enif_make_badarg(env);
	}

	//the buffer shouldn't be modified by the SHA functions, but you never know
	// for now I won't make a copy, but if funny things happen, then I will have to.	
	RIPEMD160 c = RIPEMD160();
	calculate_digest(env, &c, &p, &r);	

	return r;
}

ERL_NIF_TERM hash_ripemd256(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
	//get the buffer
	ErlNifBinary p;
	ERL_NIF_TERM r;

	if (!enif_inspect_binary(env, argv[0], &p)) {
		return enif_make_badarg(env);
	}

	//the buffer shouldn't be modified by the SHA functions, but you never know
	// for now I won't make a copy, but if funny things happen, then I will have to.	
	RIPEMD256 c = RIPEMD256();
	calculate_digest(env, &c, &p, &r);	

	return r;
}

ERL_NIF_TERM hash_ripemd320(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
	//get the buffer
	ErlNifBinary p;
	ERL_NIF_TERM r;

	if (!enif_inspect_binary(env, argv[0], &p)) {
		return enif_make_badarg(env);
	}

	//the buffer shouldn't be modified by the SHA functions, but you never know
	// for now I won't make a copy, but if funny things happen, then I will have to.	
	RIPEMD320 c = RIPEMD320();
	calculate_digest(env, &c, &p, &r);	

	return r;
}


ERL_NIF_TERM hash_tiger(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
	//get the buffer
	ErlNifBinary p;
	ERL_NIF_TERM r;

	if (!enif_inspect_binary(env, argv[0], &p)) {
		return enif_make_badarg(env);
	}

	//the buffer shouldn't be modified by the SHA functions, but you never know
	// for now I won't make a copy, but if funny things happen, then I will have to.	
	Tiger c = Tiger();
	calculate_digest(env, &c, &p, &r);	

	return r;
}

ERL_NIF_TERM hash_whirlpool(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
	//get the buffer
	ErlNifBinary p;
	ERL_NIF_TERM r;

	if (!enif_inspect_binary(env, argv[0], &p)) {
		return enif_make_badarg(env);
	}

	//the buffer shouldn't be modified by the SHA functions, but you never know
	// for now I won't make a copy, but if funny things happen, then I will have to.	
	Whirlpool c = Whirlpool();
	calculate_digest(env, &c, &p, &r);	

	return r;
}

ERL_NIF_TERM hash_md2(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
	//get the buffer
	ErlNifBinary p;
	ERL_NIF_TERM r;

	if (!enif_inspect_binary(env, argv[0], &p)) {
		return enif_make_badarg(env);
	}

	//the buffer shouldn't be modified by the SHA functions, but you never know
	// for now I won't make a copy, but if funny things happen, then I will have to.	
	Weak1::MD2 c = Weak1::MD2();
	calculate_digest(env, &c, &p, &r);	

	return r;
}
ERL_NIF_TERM hash_md4(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
	//get the buffer
	ErlNifBinary p;
	ERL_NIF_TERM r;

	if (!enif_inspect_binary(env, argv[0], &p)) {
		return enif_make_badarg(env);
	}

	//the buffer shouldn't be modified by the SHA functions, but you never know
	// for now I won't make a copy, but if funny things happen, then I will have to.	
	Weak1::MD4 c = Weak1::MD4();
	calculate_digest(env, &c, &p, &r);	

	return r;
}

ERL_NIF_TERM hash_md5(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
	//get the buffer
	ErlNifBinary p;
	ERL_NIF_TERM r;

	if (!enif_inspect_binary(env, argv[0], &p)) {
		return enif_make_badarg(env);
	}

	//the buffer shouldn't be modified by the SHA functions, but you never know
	// for now I won't make a copy, but if funny things happen, then I will have to.	
	Weak1::MD5 c = Weak1::MD5();
	calculate_digest(env, &c, &p, &r);	

	return r;
}
