#include "ecdsa.h"

#include <asn.h>
#include <eccrypto.h>
#include <ecp.h>
#include <cryptlib.h>
#include <queue.h>
#include <integer.h>
#include <osrng.h>

#include <sha.h>

#include <oids.h>

using namespace CryptoPP;
using namespace CryptoPP::ASN1;
using namespace std;

using CryptoPP::ByteQueue;
using CryptoPP::ECP;
using CryptoPP::ECDSA;
using CryptoPP::Integer;
using CryptoPP::OID;

//initialise the Private Key with the chosen ec_curve, if this is not right then it will crash erl
// the appropriate check should be done in the Erlang module to prevent the function from calling
// the incorrect EC_curve.
DL_GroupParameters_EC<ECP> getECCurve(char* ec_curve) {
	string ecStr(ec_curve);
	if (ecStr.compare(string("secp112r1")) == 0)
		return ASN1::secp112r1();
	else if (ecStr.compare(string("secp112r2")) == 0)
		return ASN1::secp112r2();
	else if (ecStr.compare(string("secp160r1")) == 0)
		return ASN1::secp160r1();
	else if (ecStr.compare(string("secp160k1")) == 0)
		return ASN1::secp160k1();
	else if (ecStr.compare(string("secp256k1")) == 0)
		return ASN1::secp256k1();
	else if (ecStr.compare(string("secp128r1")) == 0)
		return ASN1::secp128r1();
	else if (ecStr.compare(string("secp128r2")) == 0)
		return ASN1::secp128r2();
	else if (ecStr.compare(string("secp160r2")) == 0)
		return ASN1::secp160r2();
	else if (ecStr.compare(string("secp192k1")) == 0)
		return ASN1::secp192k1();
	else if (ecStr.compare(string("secp224k1")) == 0)
		return ASN1::secp224k1();
	else if (ecStr.compare(string("secp224r1")) == 0)
		return ASN1::secp224r1();
	else if (ecStr.compare(string("secp384r1")) == 0)
		return ASN1::secp384r1();
	else if (ecStr.compare(string("secp521r1")) == 0)
		return ASN1::secp521r1();
	return ASN1::secp256k1();	//default use this key to prevent a crash
}

void initializePrivateKey(char* ec_curve, ECDSA<ECP, SHA256>::PrivateKey& PrivateKey, const Integer& key) {
	PrivateKey.Initialize(getECCurve(ec_curve), key);
}

void initializePrivateKey(char* ec_curve, ECDSA<ECP, SHA256>::PrivateKey& PrivateKey) {
	AutoSeededRandomPool prng;
	PrivateKey.Initialize(prng, getECCurve(ec_curve));
}

ERL_NIF_TERM ecdsa_generate_public_key(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
	//this will contain the private key that will be used to initilise and
	//generate the private key.
	ErlNifBinary privKey;
	char ec_curve[32];
	memset(ec_curve, 0x00, sizeof(ec_curve));
	ERL_NIF_TERM out;
	
	if (!enif_get_atom(env, argv[0], ec_curve, sizeof(ec_curve), ERL_NIF_LATIN1)) {
		return enif_make_badarg(env);
	}

	//this is the private key	
	if (!enif_inspect_binary(env, argv[1], &privKey)) {
		return enif_make_badarg(env);
	}
	
	//initialise the key from the byte array passed by the user.
	Integer key(privKey.data, privKey.size);
	
	//generate the private and public key containers
	ECDSA<ECP, SHA256>::PrivateKey privateKey;
	ECDSA<ECP, SHA256>::PublicKey publicKey;

	initializePrivateKey(ec_curve, privateKey, key);	
	privateKey.MakePublicKey(publicKey);	//get the corresponding public key

	const ECP::Point& q = publicKey.GetPublicElement();
	const Integer& px = q.x;
	const Integer& py = q.y;

	ByteQueue keyOutput;
	
	//output an uncompressed SEC private key
	keyOutput.Put(4);
	px.Encode(keyOutput, px.ByteCount());
	py.Encode(keyOutput, py.ByteCount());

	//copy the output to the term
	byte* publiKeyBuffer = (byte*)enif_make_new_binary(env, keyOutput.MaxRetrievable(), &out);
	keyOutput.Get(publiKeyBuffer, keyOutput.MaxRetrievable());
	
	return out;
}

ERL_NIF_TERM ecdsa_generate_private_key(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
	//get the cruve name
	char ec_curve[32];
	ERL_NIF_TERM out;

	memset(ec_curve, 0x00, sizeof(ec_curve));

	if (!enif_get_atom(env, argv[0], ec_curve, sizeof(ec_curve), ERL_NIF_LATIN1)) {
		return enif_make_badarg(env);
	}

	ECDSA<ECP, SHA256>::PrivateKey privateKey;
	initializePrivateKey(ec_curve, privateKey);

	//get the private key
	ByteQueue keyOutput;
	const Integer& x1 = privateKey.GetPrivateExponent();
	
	x1.Encode(keyOutput, x1.ByteCount());

	//copy out the private key
	byte* privateKeyBuffer = (byte*)enif_make_new_binary(env, keyOutput.MaxRetrievable(), &out);
	keyOutput.Get(privateKeyBuffer, keyOutput.MaxRetrievable());

	return out;
}
