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

void initializePrivateKey(char* ec_curve, ECDSA<ECP, SHA1>::PrivateKey& PrivateKey, const Integer& key) {
	PrivateKey.Initialize(getECCurve(ec_curve), key);
}

void initializePrivateKey(char* ec_curve, ECDSA<ECP, SHA1>::PrivateKey& PrivateKey) {
	AutoSeededRandomPool prng;
	PrivateKey.Initialize(prng, getECCurve(ec_curve));
}

//get the byte size of the modulus as a reasonable estimate for padding points.
int get_point_size(char* ec_curve) {
	DL_GroupParameters_EC<ECP> params = getECCurve(ec_curve);
	return params.GetSubgroupOrder().ByteCount();
}

//a simple function to place some extra padding on the queue if needed
void putpadding(ByteQueue& queue, int count) {
	if (count <= 0)
		return;
	queue.Put(0);
	putpadding(queue, count--);
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
	ECDSA<ECP, SHA1>::PrivateKey privateKey;
	ECDSA<ECP, SHA1>::PublicKey publicKey;

	initializePrivateKey(ec_curve, privateKey, key);	
	privateKey.MakePublicKey(publicKey);	//get the corresponding public key

	const ECP::Point& q = publicKey.GetPublicElement();
	const Integer& px = q.x;
	const Integer& py = q.y;

	ByteQueue keyOutput;
	
	//output an uncompressed SEC private key
	int PointSize = get_point_size(ec_curve);
	keyOutput.Put(4);
	
	//a holding buffer for the output points
	byte xBuffer[PointSize];
	byte yBuffer[PointSize];
	memset(xBuffer, 0, sizeof(xBuffer));
	memset(yBuffer, 0, sizeof(yBuffer));
	
	px.Encode(xBuffer+(PointSize-px.ByteCount()), px.ByteCount());
	py.Encode(yBuffer+(PointSize-py.ByteCount()), py.ByteCount());

	keyOutput.Put(xBuffer, sizeof(xBuffer));
	keyOutput.Put(yBuffer, sizeof(yBuffer));

	//copy the output to the term
	byte* publicKeyBuffer = (byte*)enif_make_new_binary(env, keyOutput.MaxRetrievable(), &out);
	keyOutput.Get(publicKeyBuffer, keyOutput.MaxRetrievable());
	
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

	ECDSA<ECP, SHA1>::PrivateKey privateKey;
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

ERL_NIF_TERM ecdsa_get_base_point(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
	char ec_curve[32];

	//out binaries
	ERL_NIF_TERM outX;
	ERL_NIF_TERM outY;

	//get the curve name
	if (!enif_get_atom(env, argv[0], ec_curve, sizeof(ec_curve), ERL_NIF_LATIN1)) {
		return enif_make_badarg(env);
	}

	//get the base point and return to the user
	DL_GroupParameters_EC<ECP> params = getECCurve(ec_curve);
	const ECP::Point& basePoint = params.GetSubgroupGenerator();
	
	//now marshall the points back to binaries
	byte* outXbuffer = (byte*)enif_make_new_binary(env, basePoint.x.ByteCount(), &outX);
	basePoint.x.Encode(outXbuffer, basePoint.x.ByteCount());

	byte* outYbuffer = (byte*)enif_make_new_binary(env, basePoint.y.ByteCount(), &outY);
	basePoint.y.Encode(outYbuffer, basePoint.y.ByteCount());

	return enif_make_tuple(env, 2, outX, outY);
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
		enif_inspect_binary(env, point2[i], &(p2[i]));
	}
	
	Integer x1(p1[0].data, p1[0].size);
	Integer y1(p1[1].data, p1[1].size);
	Integer x2(p2[0].data, p2[0].size);
	Integer y2(p2[1].data, p2[1].size);

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

ERL_NIF_TERM ecdsa_point_multiplication(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
	//add points together in the finite field
	char ec_curve[32];
	ErlNifBinary inInteger;
	int pointArity;
	const ERL_NIF_TERM* point;

	//out binaries
	ERL_NIF_TERM outX;
	ERL_NIF_TERM outY;

	memset(ec_curve, 0x00, sizeof(ec_curve));

	//param1 - curve name
	if (!enif_get_atom(env, argv[0], ec_curve, sizeof(ec_curve), ERL_NIF_LATIN1)) {
		return enif_make_badarg(env);
	}

	//Integer - The input Integer
	if (!enif_inspect_binary(env, argv[1], &inInteger)) {
		return enif_make_badarg(env);
	}

	//Point - The point to multiply by
	if (!enif_get_tuple(env, argv[2], &pointArity, &point)) {
		return enif_make_badarg(env);
	}
	
	Integer intMul(inInteger.data, inInteger.size);

	//read each of the points as binarys these will then be converted to an integer
	// the input point should be a tuple of the form {x,y} where x and y are binarys
	ErlNifBinary p[pointArity];
	for (int i = 0; i < pointArity; i++) {
		enif_inspect_binary(env, point[i], &(p[i]));
	}
	Integer x(p[0].data, p[0].size);
	Integer y(p[1].data, p[1].size);

	//create the ECPoint
	ECP::Point curvePoint(x, y);

	//get the domain parameters
	DL_GroupParameters_EC<ECP> params = getECCurve(ec_curve);
	const Integer& n = params.GetCurve().GetField().GetModulus();
	const Integer& a = params.GetCurve().GetA();
	const Integer& b = params.GetCurve().GetB();

	//add the points together in the field
	ECP pointMul(n, a, b);
	const ECP::Point& newPnt = pointMul.Multiply(intMul, curvePoint);

	//now marshall the points back to binaries
	byte* outXbuffer = (byte*)enif_make_new_binary(env, newPnt.x.ByteCount(), &outX);
	newPnt.x.Encode(outXbuffer, newPnt.x.ByteCount());

	byte* outYbuffer = (byte*)enif_make_new_binary(env, newPnt.y.ByteCount(), &outY);
	newPnt.y.Encode(outYbuffer, newPnt.y.ByteCount());

	return enif_make_tuple(env, 2, outX, outY);
}

//decode a compressed point and return the X, Y coordinates as a tuple of {X,Y}
//param1 - curve/atom, param2 - point/binary
//Return - a tuple of {X/binary, Y/binary}.
ERL_NIF_TERM ecdsa_decode_point(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
	char ec_curve[32];
	ErlNifBinary point;

	//out binaries
	ERL_NIF_TERM outX;
	ERL_NIF_TERM outY;

	memset(ec_curve, 0x00, sizeof(ec_curve));

	//param1 - curve name
	if (!enif_get_atom(env, argv[0], ec_curve, sizeof(ec_curve), ERL_NIF_LATIN1)) {
		return enif_make_badarg(env);
	}

	//param2 - compressed point/binary
	if (!enif_inspect_binary(env, argv[1], &point)) {
		return enif_make_badarg(env);
	}	

	//get the domain parameters
	DL_GroupParameters_EC<ECP> params = getECCurve(ec_curve);
	const Integer& n = params.GetCurve().GetField().GetModulus();
	const Integer& a = params.GetCurve().GetA();
	const Integer& b = params.GetCurve().GetB();

	ECP decoder(n, a, b);
	ECP::Point newPnt;
	if (decoder.DecodePoint(newPnt, (const byte*)point.data, point.size)) {
		//now marshall the points back to binaries
		byte* outXbuffer = (byte*)enif_make_new_binary(env, newPnt.x.ByteCount(), &outX);
		newPnt.x.Encode(outXbuffer, newPnt.x.ByteCount());

		byte* outYbuffer = (byte*)enif_make_new_binary(env, newPnt.y.ByteCount(), &outY);
		newPnt.y.Encode(outYbuffer, newPnt.y.ByteCount());

		//return the decoded point
		return enif_make_tuple(env, 2, outX, outY);
	}
	return enif_make_tuple(env, 2, enif_make_atom(env, "error\0"), enif_make_atom(env, "invalid_point\0")); 

}

// Sign a message with an ECDSA private key - the message is a binary string
// Param1 - curve/atom, Param 2 - Private Key/binary, Param 3 - Message/binary
// Return Signature/binary - this signature is in IEEE P1363 format, this is a
// concatination of r and s
ERL_NIF_TERM ecdsa_sign(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
	ERL_NIF_TERM out;
	ErlNifBinary privKey;
	ErlNifBinary message;
	AutoSeededRandomPool prng;	//used for signing
	char ec_curve[32];

	//get the data and the signature
	//param1 - curve name
	if (!enif_get_atom(env, argv[0], ec_curve, sizeof(ec_curve), ERL_NIF_LATIN1)) {
		return enif_make_badarg(env);
	}

	//param2 - private key
	if (!enif_inspect_binary(env, argv[1], &privKey)) {
		return enif_make_badarg(env);
	}

	//param2 - message
	if (!enif_inspect_binary(env, argv[2], &message)) {
		return enif_make_badarg(env);
	}

	//Populate Private Key
	ECDSA<ECP, SHA1>::PrivateKey privateKey;
	Integer key(privKey.data, privKey.size);
	initializePrivateKey(ec_curve, privateKey, key);

	//create a signer
	ECDSA<ECP, SHA1>::Signer signer(privateKey);
	int SignatureLength = signer.MaxSignatureLength();
	byte signature[SignatureLength];
	memset(signature, 0x00, SignatureLength);

	//sign the message
	int sigLength = signer.SignMessage(prng, (const byte*)message.data, message.size, signature);
	
	//copy out the signature to the term
	byte* outBuffer = (byte*)enif_make_new_binary(env, sigLength, &out);
	memcpy(outBuffer, signature, sigLength);
	memset(signature, 0x00, SignatureLength);
	
	return out;	
}

// Verify a message with an ECDSA public key - the message is a binary string
// Param1 - curve/atom, Param 2 - public Key/tuple {X,Y}, Param 3 - Message/binary
// Param4 - Signature/binary
// Return true/false
ERL_NIF_TERM ecdsa_verify(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
	int pubKeyArity;
	const ERL_NIF_TERM* pubKey;

	ErlNifBinary pubKeyX;
	ErlNifBinary pubKeyY;

	ErlNifBinary message;
	ErlNifBinary signature;
	char ec_curve[32];

	//get the data and the signature
	//param1 - curve name
	if (!enif_get_atom(env, argv[0], ec_curve, sizeof(ec_curve), ERL_NIF_LATIN1)) {
		return enif_make_badarg(env);
	}

	//param2 - public key tuple of {x,y}
	if (!enif_get_tuple(env, argv[1], &pubKeyArity, &pubKey)) {
		return enif_make_badarg(env);
	}

	//param3 - message
	if (!enif_inspect_binary(env, argv[2], &message)) {
		return enif_make_badarg(env);
	}

	//param4 - signature
	if (!enif_inspect_binary(env, argv[3], &signature)) {
		return enif_make_badarg(env);
	}

	//TODO: Check that the arity of the tuple is 2
	//extract the integer components from the public key
	enif_inspect_binary(env, pubKey[0], &pubKeyX);
	enif_inspect_binary(env, pubKey[1], &pubKeyY);

	//Populate Private Key
	ECDSA<ECP, SHA1>::PublicKey publicKey;
	ECP::Point q(Integer(pubKeyX.data, pubKeyX.size), Integer(pubKeyY.data, pubKeyY.size));
	publicKey.Initialize(getECCurve(ec_curve), q);

	//create a signer
	ECDSA<ECP, SHA1>::Verifier verifier(publicKey);

	//sign the message
	bool result = verifier.VerifyMessage((const byte*)message.data, message.size, (const byte*)signature.data, signature.size);
	
	if (result)
		return enif_make_atom(env, "true\0");	
	return enif_make_atom(env, "false\0");
}
