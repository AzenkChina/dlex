cmake_minimum_required(VERSION 3.6)

#Firstly, define the project name
project(dlex LANGUAGES C CXX)

#Secondly, indexing the project files & search paths
set(sources 
 ./libraries/library/aes.c
 ./libraries/library/aesni.c
 ./libraries/library/arc4.c
 ./libraries/library/aria.c
 ./libraries/library/asn1parse.c
 ./libraries/library/asn1write.c
 ./libraries/library/base64.c
 ./libraries/library/bignum.c
 ./libraries/library/blowfish.c
 ./libraries/library/camellia.c
 ./libraries/library/ccm.c
 ./libraries/library/certs.c
 ./libraries/library/chacha20.c
 ./libraries/library/chachapoly.c
 ./libraries/library/cipher.c
 ./libraries/library/cipher_wrap.c
 ./libraries/library/cmac.c
 ./libraries/library/ctr_drbg.c
 ./libraries/library/debug.c
 ./libraries/library/des.c
 ./libraries/library/dhm.c
 ./libraries/library/ecdh.c
 ./libraries/library/ecdsa.c
 ./libraries/library/ecjpake.c
 ./libraries/library/ecp.c
 ./libraries/library/ecp_curves.c
 ./libraries/library/entropy.c
 ./libraries/library/entropy_poll.c
 ./libraries/library/error.c
 ./libraries/library/gcm.c
 ./libraries/library/havege.c
 ./libraries/library/hkdf.c
 ./libraries/library/hmac_drbg.c
 ./libraries/library/md.c
 ./libraries/library/md_wrap.c
 ./libraries/library/md2.c
 ./libraries/library/md4.c
 ./libraries/library/md5.c
 ./libraries/library/memory_buffer_alloc.c
 ./libraries/library/net_sockets.c
 ./libraries/library/nist_kw.c
 ./libraries/library/oid.c
 ./libraries/library/padlock.c
 ./libraries/library/pem.c
 ./libraries/library/pk.c
 ./libraries/library/pk_wrap.c
 ./libraries/library/pkcs5.c
 ./libraries/library/pkcs11.c
 ./libraries/library/pkcs12.c
 ./libraries/library/pkparse.c
 ./libraries/library/pkwrite.c
 ./libraries/library/platform.c
 ./libraries/library/platform_util.c
 ./libraries/library/poly1305.c
 ./libraries/library/ripemd160.c
 ./libraries/library/rsa.c
 ./libraries/library/rsa_internal.c
 ./libraries/library/sha1.c
 ./libraries/library/sha256.c
 ./libraries/library/sha512.c
 ./libraries/library/ssl_cache.c
 ./libraries/library/ssl_ciphersuites.c
 ./libraries/library/ssl_cli.c
 ./libraries/library/ssl_cookie.c
 ./libraries/library/ssl_srv.c
 ./libraries/library/ssl_ticket.c
 ./libraries/library/ssl_tls.c
 ./libraries/library/threading.c
 ./libraries/library/timing.c
 ./libraries/library/version.c
 ./libraries/library/version_features.c
 ./libraries/library/x509.c
 ./libraries/library/x509_create.c
 ./libraries/library/x509_crl.c
 ./libraries/library/x509_crt.c
 ./libraries/library/x509_csr.c
 ./libraries/library/x509write_crt.c
 ./libraries/library/x509write_csr.c
 ./libraries/library/xtea.c
 dlex.cpp)

#Specify the compile parameters
set(CMAKE_C_FLAGS "-std=c99 -ffunction-sections -fdata-sections -Os -s")
set(CMAKE_CXX_FLAGS "-std=c++11 -ffunction-sections -fdata-sections -Os -s")
set(CMAKE_EXE_LINKER_FLAGS "-Wl,-gc-sections")

#Make project
include_directories("." "./libraries")
add_executable(${PROJECT_NAME} ${sources})
