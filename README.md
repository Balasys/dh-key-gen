# Diffie-Hellman key generator

The `dh_key_gen` tool can generate Diffie-Hellman public/private keys with several
cryptographic libraries to measure key generation speed. The following
cryptographic libraries are supported:

* OpenSSL 1.0
* OpenSSL 1.1
* OpenSSL 3.0
* BoringSSL
* LibreSSL
* wolfSSL
* mbedTLS

## Building

### Dependencies

#### OpenSSL 1.0

```
export CFLAGS=-fPIC
./config --shared
make -j build_crypto
```

#### OpenSSL >= 1.1

```
./config
make -j build_libs
```

#### BoringSSL

```
mkdir build
cd build
cmake -DBUILD_SHARED_LIBS=1 ..
make crypto
```

#### LibreSSL

```
./autogen.sh
./configure
make
```

#### WolfSSL

```
./autogen.sh
./configure --enable-opensslall --with-max-rsa-bits=8192
make
```

### Tool

```
$ mkdir build
$ cd build
$ cmake \
  -DOPENSSL_1_0_SOURCE_PATH=/path/to/compiled/openssl1_0/source/ \
  -DOPENSSL_1_1_SOURCE_PATH=/path/to/compiled/openssl1_1/source/ \
  -DOPENSSL_3_0_SOURCE_PATH=/path/to/compiled/openssl3_0/source/ \
  -DBORINGSSL_SOURCE_PATH=/path/to/compiled/boringssl/source/ \
  -DLIBRESSL_SOURCE_PATH=/path/to/compiled/libressl/source \
  ..
$ make
```

### Run

```
./dh_key_gen_lib_postfix --param-type ffdhe --param-size 8192 --priv-key-size 512 --count 100 --log
```

## License

The code is available under the terms of Apache License Version 2.0.
A non-comprehensive, but straightforward description and also the full license text can be found at
[Choose an open source license](https://choosealicense.com/licenses/apache-2.0/) website.
