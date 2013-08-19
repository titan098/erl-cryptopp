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

ERL_NIF_TERM ecdsa_get_modulus(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
	//get the cruve name
	char ec_curve[32];
	ERL_NIF_TERM out;

	memset(ec_curve, 0x00, sizeof(ec_curve));

	if (!enif_get_atom(env, argv[0], ec_curve, sizeof(ec_curve), ERL_NIF_LATIN1)) {
		return enif_make_badarg(env);
	}

	//get the domain parameters
	DL_GroupParameters_EC<ECP> params = getECCurve(ec_curve);
	const Integer& n = params.GetSubgroupOrder();

	//get the private key
	ByteQueue modOut;
	
	n.Encode(modOut, n.ByteCount());

	//copy out the private key
	byte* buffer = (byte*)enif_make_new_binary(env, modOut.MaxRetrievable(), &out);
	modOut.Get(buffer, modOut.MaxRetrievable());

	return out;
}

ERL_NIF_TERM ecdsa_point_addition(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
	//add points together in the finite field
	char ec_curve[32];
	int arity1;	//arity of each of the tuples
	int arity2;
	const ERL_NIF_TERM* point1;
	const ERL_NIF_TERM* point2;

	//out binaries
	ERL_NIF_TERM outX;
	ERL_NIF_TERM outY;

	//out tuple
	ERL_NIF_TERM outTuple;

	memset(ec_curve, 0x00, sizeof(ec_curve));

	//param1 - curve name
	if (!enif_get_atom(env, argv[0], ec_curve, sizeof(ec_curve), ERL_NIF_LATIN1)) {
		return enif_make_badarg(env);
	}

	//point 1
	if (!enif_get_tuple(env, argv[1], &arity1, &point1)) {
		return enif_make_badarg(env);
	}

	//point 2
	if (!enif_get_tuple(env, argv[2], &arity2, &point2)) {
		return enif_make_badarg(env);
	}

	//the points should be expressed as binaries to help marshal it to this function
	//these should be converted to Integers (cryptoPP)
	ErlNifBinary p1[2];
	ErlNifBinary p2[2];

	for (int i = 0; i < arity1; i++) {
		enif_inspect_binary(env, point1[i], &(p1[i]));
		enif_inspect_binary(env, point1[i], &(p2[i]));
	}
	
	Integer x1(p1[0].data, p1[0].size);
	Integer y1(p1[0].data, p1[0].size);
	Integer x2(p1[1].data, p1[1].size);
	Integer y2(p1[1].data, p1[1].size);

	ECP::Point pnt1(x1, y1);
	ECP::Point pnt2(x2, y2);

	//get the domain parameters
	DL_GroupParameters_EC<ECP> params = getECCurve(ec_curve);
	const Integer& n = params.GetCurve().GetField().GetModulus();
	const Integer& a = params.GetCurve().GetA();
	const Integer& b = params.GetCurve().GetB();

	//add the points together in the field
	ECP pointAdder(n, a, b);
	const ECP::Point& newPnt = pointAdder.Add(pnt1, pnt2);

	//now marshall the points back to binaries
	byte* outXbuffer = (byte*)enif_make_new_binary(env, newPnt.x.ByteCount(), &outX);
	newPnt.x.Encode(outXbuffer, newPnt.x.ByteCount());

	byte* outYbuffer = (byte*)enif_make_new_binary(env, newPnt.y.ByteCount(), &outY);
	newPnt.y.Encode(outYbuffer, newPnt.y.ByteCount());

	return enif_make_tuple(env, 2, outX, outY);
}
