%%
%% A cryptopp wrapper for Erlang
%% This library uses NIF functions to link to a CryptoPP shared library
%%
%% Author: David Ellefsen <davidellefsen@gmail.com>
%%
%% Copyright 2015 David Ellefsen
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%% 
%%    http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

-module(cryptopp).

%hash functions
-export([sha1/1, sha224/1, sha256/1, sha384/1, sha512/1, sha/2]).
-export([sha3_224/1, sha3_256/1, sha3_384/1, sha3_512/1, sha3/2]).
-export([ripemd128/1, ripemd160/1, ripemd256/1, ripemd320/1, ripemd/2]).
-export([tiger/1, whirlpool/1]).
-export([md2/1, md4/1, md5/1]).

-export([hmac_sha512/2]).

%ecdsa functions
-export([ecdsa_generate_public_key/2, ecdsa_generate_private_key/1]).
-export([ecdsa_get_modulus/1, ecdsa_point_addition/3, ecdsa_compress_point/1, ecdsa_decode_point/2]).
-export([ecdsa_get_base_point/1]).
-export([ecdsa_sign/3, ecdsa_verify/4, ecdsa_verify/5]).

-compile([export_all, debug_info]).

-define(NOT_LOADED, not_loaded(?LINE)).

-on_load(init/0).

sha(sha1, B) when is_binary(B) ->
	nif_hash_sha1(B);
sha(sha224, B) when is_binary(B) ->
	nif_hash_sha224(B);
sha(sha256, B) when is_binary(B) ->
	nif_hash_sha256(B);
sha(sha384, B) when is_binary(B) ->
	nif_hash_sha384(B);
sha(sha512, B) when is_binary(B) ->
	nif_hash_sha512(B).

sha1(B) ->
	sha(sha1, B).
sha224(B) ->
	sha(sha224, B).
sha256(B) ->
	sha(sha256, B).
sha384(B) ->
	sha(sha384, B).
sha512(B) ->
	sha(sha512, B).

sha3(sha3_224, B) when is_binary(B) ->
	nif_hash_sha3_224(B);
sha3(sha3_256, B) when is_binary(B) ->
	nif_hash_sha3_256(B);
sha3(sha3_384, B) when is_binary(B) ->
	nif_hash_sha3_384(B);
sha3(sha3_512, B) when is_binary(B) ->
	nif_hash_sha3_512(B).

sha3_224(B) ->
	sha3(sha3_224, B).
sha3_256(B) ->
	sha3(sha3_256, B).
sha3_384(B) ->
	sha3(sha3_384, B).
sha3_512(B) ->
	sha3(sha3_512, B).

ripemd(ripemd128, B) when is_binary(B) ->
	nif_hash_ripemd128(B);
ripemd(ripemd160, B) when is_binary(B) ->
	nif_hash_ripemd160(B);
ripemd(ripemd256, B) when is_binary(B) ->
	nif_hash_ripemd256(B);
ripemd(ripemd320, B) when is_binary(B) ->
	nif_hash_ripemd320(B).

ripemd128(B) ->
	ripemd(ripemd128, B).
ripemd160(B) ->
	ripemd(ripemd160, B).
ripemd256(B) ->
	ripemd(ripemd256, B).
ripemd320(B) ->
	ripemd(risecp256r1pemd320, B).

tiger(B) when is_binary(B) ->
	nif_hash_tiger(B).

whirlpool(B) when is_binary(B) ->
	nif_hash_whirlpool(B).

md2(B) when is_binary(B) ->
	nif_hash_md2(B).

md4(B) when is_binary(B) ->
	nif_hash_md4(B).

md5(B) when is_binary(B) ->
	nif_hash_md5(B).

%% HMAC Functions
hmac_sha512(Key, Data) when is_binary(Key) and is_binary(Data) ->
	nif_hmac_sha512(Key, Data).

%% ECDSA Functions
ecdsa_generate_public_key(secp112r1, B) when is_binary(B) ->
	nif_ecdsa_generate_public_key(secp112r1, B);
ecdsa_generate_public_key(secp160ecdsa_point_additionr1, B) when is_binary(B) ->
	nif_ecdsa_generate_public_key(secp160r1, B);
ecdsa_generate_public_key(secp160k1, B) when is_binary(B) ->
	nif_ecdsa_generate_public_key(secp160k1, B);
ecdsa_generate_public_key(secp256k1, B) when is_binary(B) ->
	nif_ecdsa_generate_public_key(secp256k1, B);
ecdsa_generate_public_key(secp128r1, B) when is_binary(B) ->
	nif_ecdsa_generate_public_key(secp128r1, B);
ecdsa_generate_public_key(secp128r2, B) when is_binary(B) ->
	nif_ecdsa_generate_public_key(secp128r2, B);
ecdsa_generate_public_key(secp160r2, B) when is_binary(B) ->
	nif_ecdsa_generate_public_key(secp160r2, B);
ecdsa_generate_public_key(secp192k1, B) when is_binary(B) ->
	nif_ecdsa_generate_public_key(secp192k1, B);
ecdsa_generate_public_key(secp224k1, B) when is_binary(B) ->
	nif_ecdsa_generate_public_key(secp224k1, B);
ecdsa_generate_public_key(secp224r1, B) when is_binary(B) ->
	nif_ecdsa_generate_public_key(sec224r1, B);
ecdsa_generate_public_key(secp384r1, B) when is_binary(B) ->
	nif_ecdsa_generate_public_key(secp384r1, B);
ecdsa_generate_public_key(secp521r1, B) when is_binary(B) ->
	nif_ecdsa_generate_public_key(secp521r1, B);
ecdsa_generate_public_key(Curve, B) when is_binary(B) ->
	{error, {unknown_ec_curve, Curve}}.

ecdsa_generate_private_key(secp112r1) ->
	nif_ecdsa_generate_private_key(secp112r1);
ecdsa_generate_private_key(secp160r1) ->
	nif_ecdsa_generate_private_key(secp160r1);
ecdsa_generate_private_key(secp160k1) ->
	nif_ecdsa_generate_private_key(secp160k1);
ecdsa_generate_private_key(secp256k1) ->
	nif_ecdsa_generate_private_key(secp256k1);
ecdsa_generate_private_key(secp128r1) ->
	nif_ecdsa_generate_private_key(secp128r1);
ecdsa_generate_private_key(secp128r2) ->
	nif_ecdsa_generate_private_key(secp128r2);
ecdsa_generate_private_key(secp160r2) ->
	nif_ecdsa_generate_private_key(secp160r2);
ecdsa_generate_private_key(secp192k1) ->
	nif_ecdsa_generate_private_key(secp192k1);
ecdsa_generate_private_key(secp224k1) ->
	nif_ecdsa_generate_private_key(secp224k1);
ecdsa_generate_private_key(secp224r1) ->
	nif_ecdsa_generate_private_key(sec224r1);
ecdsa_generate_private_key(secp384r1) ->
	nif_ecdsa_generate_private_key(secp384r1);
ecdsa_generate_private_key(secp521r1) ->
	nif_ecdsa_generate_private_key(secp521r1);
ecdsa_generate_private_key(Curve) ->
	{error, {unknown_ec_curve, Curve}}.

ecdsa_get_modulus(Curve) when is_atom(Curve) ->
	Mod = nif_ecdsa_get_modulus(Curve),
	binary:decode_unsigned(Mod).

ecdsa_point_addition(Curve, Point1, Point2) ->
	nif_ecdsa_point_addition(Curve, Point1, Point2).

% Create a point on the specified curve through point multiplication with the base point
ecdsa_get_base_point(Curve) ->
	nif_ecdsa_get_base_point(Curve).

ecdsa_point_multiplication(Curve, Integer, Point) ->
	nif_ecdsa_point_multiplication(Curve, Integer, Point).

%Decode a uncompressed key so that it is in point form to be sent to the
% verification functions.
ecdsa_decode_public_key(UncompressedKey) when is_binary(UncompressedKey) ->
	KeySize = (byte_size(UncompressedKey)-1) div 2,
	<<4, X:KeySize/binary, Y:KeySize/binary>> = UncompressedKey,
	{X, Y}.

ecdsa_encode_public_key({X, Y}) ->
	<<4, X/binary, Y/binary>>.

%%Encode the point as in compressed SEC form
ecdsa_compress_point({X,Y}) ->
	Parity = case (binary:decode_unsigned(Y) rem 2) of
			0 -> 2;
			1 -> 3
		 end,
	<<Parity, X/binary>>;	
ecdsa_compress_point(UncompressedPoint) when is_binary(UncompressedPoint) ->
	{X, Y} = ecdsa_decode_public_key(UncompressedPoint),
	ecdsa_compress_point({X,Y}).

%%Decode a point that is in compressed SEC form
ecdsa_decode_point(Curve, CompressedPoint) when is_binary(CompressedPoint) ->
	nif_ecdsa_decode_point(Curve, CompressedPoint).

%% Signature verification and Signing functions %%%
decodeIEEEP1363(Signature) ->
	ByteSize = (byte_size(Signature)*8) div 2,
	<<R:ByteSize, S:ByteSize, _Rest/binary>> = Signature,
	{R, S}.

%% Decode a ECDSA-Sig-Value from a passed DER structure
decodeECDSADer(Signature) when is_binary(Signature) ->
	case 'EccSignature':decode('ECDSA-Sig-Value', Signature) of 
		{ok, ECDSASignature} -> ECDSASignature;
		{error, _Msg} -> {error, could_not_decode_signature}
	end.

%% Sign a message using a passed private key
ecdsa_sign(Curve, PrivateKey, Message) ->
	nif_ecdsa_sign(Curve, PrivateKey, Message).

%% Sign a message using a passed private key and return the result as a DER formatted structure
ecdsa_sign(Curve, PrivateKey, Message, der) ->
	{R, S} = decodeIEEEP1363(nif_ecdsa_sign(Curve, PrivateKey, Message)),
	case 'EccSignature':encode('ECDSA-Sig-Value', {'ECDSA-Sig-Value', R, S}) of
		{ok, Binary} -> Binary;
		{error, _Msg} -> {error, could_not_encode_signature}
	end.

%% Verify a message with a passed public key. ECDSA requires both the message and the signature to verify
ecdsa_verify(Curve, PublicKey, Message, Signature) ->
	nif_ecdsa_verify(Curve, PublicKey, Message, Signature).

%% Verify a message using a passed public key. The signature is encoded as a DER structure
ecdsa_verify(Curve, PublicKey, Message, Signature, der) ->
	{'ECDSA-Sig-Value', R, S} = decodeECDSADer(Signature),
	Rbin = binary:encode_unsigned(R),
	Sbin = binary:encode_unsigned(S),
	nif_ecdsa_verify(Curve, PublicKey, Message, <<Rbin/binary, Sbin/binary>>).

init() ->
	PrivDir = case code:priv_dir(?MODULE) of
		{error, _} ->
			EbinDir = filename:dirname(code:which(?MODULE)),
			AppPath = filename:dirname(EbinDir),
			filename:join(AppPath, "priv");
		Path ->
			Path
	end,
	erlang:load_nif(filename:join(PrivDir, "cryptopp"), 0).


not_loaded(Line) ->
	erlang:nif_error({not_loaded, [{module, ?MODULE}, {line, Line}]}).

nif_hash_sha1(_B) ->
	?NOT_LOADED.
nif_hash_sha224(_B) ->
	?NOT_LOADED.
nif_hash_sha256(_B) ->
	?NOT_LOADED.
nif_hash_sha384(_B) ->
	?NOT_LOADED.
nif_hash_sha512(_B) ->
	?NOT_LOADED.

nif_hash_sha3_224(_B) ->
	?NOT_LOADED.
nif_hash_sha3_256(_B) ->
	?NOT_LOADED.
nif_hash_sha3_384(_B) ->
	?NOT_LOADED.
nif_hash_sha3_512(_B) ->
	?NOT_LOADED.

nif_hash_ripemd128(_B) ->
	?NOT_LOADED.
nif_hash_ripemd160(_B) ->
	?NOT_LOADED.
nif_hash_ripemd256(_B) ->
	?NOT_LOADED.
nif_hash_ripemd320(_B) ->
	?NOT_LOADED.

nif_hash_tiger(_B) ->
	?NOT_LOADED.

nif_hash_whirlpool(_B) ->
	?NOT_LOADED.

nif_hash_md2(_B) ->
	?NOT_LOADED.
nif_hash_md4(_B) ->
	?NOT_LOADED.
nif_hash_md5(_B) ->
	?NOT_LOADED.

nif_hmac_sha512(_K, _D) ->
	?NOT_LOADED.

nif_ecdsa_generate_public_key(_Curve, _B) ->
	?NOT_LOADED.
nif_ecdsa_generate_private_key(_Curve) ->
	?NOT_LOADED.
nif_ecdsa_get_modulus(_Curve) ->
	?NOT_LOADED.
nif_ecdsa_point_addition(_Curve, _Point1, _Point2) ->
	?NOT_LOADED.
nif_ecdsa_point_multiplication(_Curve, _Integer, _Point) ->
	?NOT_LOADED.
nif_ecdsa_decode_point(_Curve, _Point) ->
	?NOT_LOADED.
nif_ecdsa_get_base_point(_Curve) ->
	?NOT_LOADED.

nif_ecdsa_sign(_Curve, _PrivateKey, _Message) ->
	?NOT_LOADED.

nif_ecdsa_verify(_Curve, _PublicKey, _Message, _Signature) ->
	?NOT_LOADED.

hex_dump(Number) ->
	A = binary_to_list(Number),
	lists:flatten(lists:map(fun hex_char/1, A)).

hex_char(X) ->
	lists:flatten(io_lib:format("~2.16.0B", [X])).
