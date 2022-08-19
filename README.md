# Diffie-Hellman key generator

The `dh_key_gen` tool can generate Diffie-Hellman public/private keys with several
cryptographic libraries to measure key generation speed. The following
cryptographic libraries are supported:

* OpenSSL 1.0
* OpenSSL 1.1
* OpenSSL 3.0

## Usage

### Build

```
$ mkdir build
$ cd build
$ cmake \
  -DOPENSSL_1_0_SOURCE_PATH=/path/to/compiled/boringssl/source/ \
  -DOPENSSL_1_1_SOURCE_PATH=/path/to/compiled/boringssl/source/ \
  -DOPENSSL_3_0_SOURCE_PATH=/path/to/compiled/boringssl/source/ \
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
