erl-cryptopp
==========

Version: 0.1.0

This project is a collection of wrapper functions for Erlang and CryptoPP. This library exposes a number  of native CryptoPP functions to the Erlang VM. The allows the user to have access to functions that are not provided by the built-in crypto module.

Building
--------

Building the library requires that CryptoPP is downloaded and compiled. This has been tested on Linux and MacOSX. ``rebar`` will handle the download and compilation of the dependencies.

To build a fresh copy of ``rebar``:

```
./makerebar.sh
```

The build erl-cryptopp:

```
./rebar compile
```

Caveats
-------

When compiling on Linux you will need to compile CryptoPP using a ``-fPIC`` flag. This will enable the generation of position independent code. This can be achieved by modifying the makefile for CryptoPP to uncomment the line ``CXXFLAGS+=-fPIC``. A ``make clean`` might be required in the CryptoPP directory to force a rebuild.

Usage
-----

The following example demonstrates the usage of this module:

```erlang
1> f().
ok
2> M = cryptopp:ecdsa_generate_private_key(secp256k1).
<<84,23,221,107,101,67,95,45,252,157,62,14,41,197,35,63,
  37,169,187,38,50,208,172,198,143,91,233,227,215,...>>
3> P = cryptopp:ecdsa_generate_public_key(secp256k1, M).
<<4,166,102,250,153,87,228,47,20,163,56,201,236,172,228,
  58,101,168,97,194,198,3,61,11,150,207,228,39,32,...>>
4> Pt = cryptopp:ecdsa_decode_public_key(P).
{<<166,102,250,153,87,228,47,20,163,56,201,236,172,228,58,
   101,168,97,194,198,3,61,11,150,207,228,39,32,...>>,
 <<94,39,42,110,99,220,244,255,249,1,240,166,213,62,213,
   244,190,209,239,68,36,118,37,241,58,152,38,...>>}
5> Pc = cryptopp:ecdsa_compress_point(P).
<<3,166,102,250,153,87,228,47,20,163,56,201,236,172,228,
  58,101,168,97,194,198,3,61,11,150,207,228,39,32,...>>
6> Sig = cryptopp:ecdsa_sign(secp256k1, M, <<1,2,3,4,5>>).
<<147,242,179,164,179,181,177,230,181,99,143,38,201,162,
  15,218,148,121,67,55,170,198,245,53,44,239,62,10,247,...>>
7> SigDer = cryptopp:ecdsa_sign(secp256k1, M, <<1,2,3,4,5>>, der).
<<48,69,2,33,0,182,27,175,61,248,21,113,109,90,194,228,
  130,246,239,150,31,128,199,182,104,243,72,75,248,...>>
8> 
8> <<R:256, S:256>> = Sig.
<<147,242,179,164,179,181,177,230,181,99,143,38,201,162,
  15,218,148,121,67,55,170,198,245,53,44,239,62,10,247,...>>
9> {ok, Bin} = 'EccSignature':encode('ECDSA-Sig-Value', {'ECDSA-Sig-Value', R, S}).
{ok,<<48,70,2,33,0,147,242,179,164,179,181,177,230,181,
      99,143,38,201,162,15,218,148,121,67,55,170,198,...>>}
10> 
10> cryptopp:ecdsa_verify(secp256k1, Pt, <<1,2,3,4,5>>, Sig).
true
11> cryptopp:ecdsa_verify(secp256k1, Pt, <<1,2,3,4,5>>, SigDer, der).
true
12> 
12> Pt == cryptopp:ecdsa_decode_point(secp256k1, P).
true
13> Pt == cryptopp:ecdsa_decode_point(secp256k1, Pc).
true
```

License
-------

This application is licensed under an [Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0.html)

    Copyright 2015 David Ellefsen 

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.



