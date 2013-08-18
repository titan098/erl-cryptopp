-module(cryptopp).

%hash functions
-export([sha1/1, sha224/1, sha256/1, sha384/1, sha512/1, sha/2]).
-export([sha3_224/1, sha3_256/1, sha3_384/1, sha3_512/1, sha3/2]).
-export([ripemd128/1, ripemd160/1, ripemd256/1, ripemd320/1, ripemd/2]).
-export([tiger/1, whirlpool/1]).
-export([md2/1, md4/1, md5/1]).

-export([hmac_sha512/2]).

%ecdsa functions
-export([ecdsa_generate_private_key/2, ecdsa_generate_private_key/1]).

-compile([export_all]).

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
	ripemd(ripemd320, B).

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
ecdsa_generate_private_key(secp112r1, B) when is_binary(B) ->
	nif_ecdsa_generate_public_key(secp112r1, B);
ecdsa_generate_private_key(secp160r1, B) when is_binary(B) ->
	nif_ecdsa_generate_public_key(secp160r1, B);
ecdsa_generate_private_key(secp160k1, B) when is_binary(B) ->
	nif_ecdsa_generate_public_key(secp160k1, B);
ecdsa_generate_private_key(secp256k1, B) when is_binary(B) ->
	nif_ecdsa_generate_public_key(secp256k1, B);
ecdsa_generate_private_key(secp128r1, B) when is_binary(B) ->
	nif_ecdsa_generate_public_key(secp128r1, B);
ecdsa_generate_private_key(secp128r2, B) when is_binary(B) ->
	nif_ecdsa_generate_public_key(secp128r2, B);
ecdsa_generate_private_key(secp160r2, B) when is_binary(B) ->
	nif_ecdsa_generate_public_key(secp160r2, B);
ecdsa_generate_private_key(secp192k1, B) when is_binary(B) ->
	nif_ecdsa_generate_public_key(secp192k1, B);
ecdsa_generate_private_key(secp224k1, B) when is_binary(B) ->
	nif_ecdsa_generate_public_key(secp224k1, B);
ecdsa_generate_private_key(secp224r1, B) when is_binary(B) ->
	nif_ecdsa_generate_public_key(sec224r1, B);
ecdsa_generate_private_key(secp384r1, B) when is_binary(B) ->
	nif_ecdsa_generate_public_key(secp384r1, B);
ecdsa_generate_private_key(secp521r1, B) when is_binary(B) ->
	nif_ecdsa_generate_public_key(secp521r1, B);
ecdsa_generate_private_key(Curve, B) when is_binary(B) ->
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

%Decode a uncompressed key so that it is in point form to be sent to the
% verification functions.
ecdsa_decode_public_key(PublicKey) when is_binary(PublicKey) ->
	KeySize = (byte_size(PublicKey)-1)/2,
	<<4, X:KeySize/binary, Y:KeySize/binary>> = PublicKey,
	{X, Y}.

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

hex_dump(Number) ->
	A = binary_to_list(Number),
	lists:flatten(lists:map(fun hex_char/1, A)).

hex_char(X) ->
	lists:flatten(io_lib:format("~2.16.0B", [X])).
