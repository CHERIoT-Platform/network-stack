-- Copyright Microsoft and CHERIoT Contributors.
-- SPDX-License-Identifier: MIT

sdkdir = "../cheriot-rtos/sdk"

set_project("CHERIoT Network Stack Example")
includes(sdkdir)
set_toolchains("cheriot-clang")

option("board")
    set_default("ibex-arty-a7-100")

option("IPv6")
    set_default(true)
    set_showmenu(true)

includes(path.join(sdkdir, "lib"))

library("time_helpers")
  add_includedirs("include")
  add_files("time-helpers.cc")

compartment("Firewall")
  add_includedirs(".", "include", "third_party/freertos-plus-tcp/source/include")
  add_includedirs("third_party/freertos")
  add_includedirs(path.join(sdkdir, "include/FreeRTOS-Compat"))
  --FIXME: The FreeRTOS compat headers need to work with this mode!
  --add_defines("CHERIOT_NO_AMBIENT_MALLOC", "CHERIOT_NO_NEW_DELETE")
  add_files("firewall.cc")

compartment("TLS")
  add_files("tls.cc")
  -- BearSSL bits:
  add_defines("BR_INT128=0", "BR_UMUL128=0", "BR_USE_UNIX_TIME=1")
  add_includedirs("include", "third_party/BearSSL/src", "third_party/BearSSL/inc")
  add_files( "src/settings.c")
  add_files(
    "third_party/BearSSL/src/aead/ccm.c",
    "third_party/BearSSL/src/aead/eax.c",
    "third_party/BearSSL/src/aead/gcm.c")
  add_files(
    "third_party/BearSSL/src/codec/ccopy.c",
    "third_party/BearSSL/src/codec/dec16be.c",
    "third_party/BearSSL/src/codec/dec16le.c",
    "third_party/BearSSL/src/codec/dec32be.c",
    "third_party/BearSSL/src/codec/dec32le.c",
    "third_party/BearSSL/src/codec/dec64be.c",
    "third_party/BearSSL/src/codec/dec64le.c",
    "third_party/BearSSL/src/codec/enc16be.c",
    "third_party/BearSSL/src/codec/enc16le.c",
    "third_party/BearSSL/src/codec/enc32be.c",
    "third_party/BearSSL/src/codec/enc32le.c",
    "third_party/BearSSL/src/codec/enc64be.c",
    "third_party/BearSSL/src/codec/enc64le.c",
    "third_party/BearSSL/src/codec/pemdec.c",
    "third_party/BearSSL/src/codec/pemenc.c")
  add_files(
    "third_party/BearSSL/src/ec/ec_all_m15.c",
    "third_party/BearSSL/src/ec/ec_all_m31.c",
    "third_party/BearSSL/src/ec/ec_c25519_i15.c",
    "third_party/BearSSL/src/ec/ec_c25519_i31.c",
    "third_party/BearSSL/src/ec/ec_c25519_m15.c",
    "third_party/BearSSL/src/ec/ec_c25519_m31.c",
    "third_party/BearSSL/src/ec/ec_c25519_m62.c",
    "third_party/BearSSL/src/ec/ec_c25519_m64.c",
    "third_party/BearSSL/src/ec/ec_curve25519.c",
    "third_party/BearSSL/src/ec/ec_default.c",
    "third_party/BearSSL/src/ec/ec_keygen.c",
    "third_party/BearSSL/src/ec/ec_p256_m15.c",
    "third_party/BearSSL/src/ec/ec_p256_m31.c",
    "third_party/BearSSL/src/ec/ec_p256_m62.c",
    "third_party/BearSSL/src/ec/ec_p256_m64.c",
    "third_party/BearSSL/src/ec/ec_prime_i15.c",
    "third_party/BearSSL/src/ec/ec_prime_i31.c",
    "third_party/BearSSL/src/ec/ec_pubkey.c",
    "third_party/BearSSL/src/ec/ec_secp256r1.c",
    "third_party/BearSSL/src/ec/ec_secp384r1.c",
    "third_party/BearSSL/src/ec/ec_secp521r1.c",
    "third_party/BearSSL/src/ec/ecdsa_atr.c",
    "third_party/BearSSL/src/ec/ecdsa_default_sign_asn1.c",
    "third_party/BearSSL/src/ec/ecdsa_default_sign_raw.c",
    "third_party/BearSSL/src/ec/ecdsa_default_vrfy_asn1.c",
    "third_party/BearSSL/src/ec/ecdsa_default_vrfy_raw.c",
    "third_party/BearSSL/src/ec/ecdsa_i15_bits.c",
    "third_party/BearSSL/src/ec/ecdsa_i15_sign_asn1.c",
    "third_party/BearSSL/src/ec/ecdsa_i15_sign_raw.c",
    "third_party/BearSSL/src/ec/ecdsa_i15_vrfy_asn1.c",
    "third_party/BearSSL/src/ec/ecdsa_i15_vrfy_raw.c",
    "third_party/BearSSL/src/ec/ecdsa_i31_bits.c",
    "third_party/BearSSL/src/ec/ecdsa_i31_sign_asn1.c",
    "third_party/BearSSL/src/ec/ecdsa_i31_sign_raw.c",
    "third_party/BearSSL/src/ec/ecdsa_i31_vrfy_asn1.c",
    "third_party/BearSSL/src/ec/ecdsa_i31_vrfy_raw.c",
    "third_party/BearSSL/src/ec/ecdsa_rta.c")
  add_files(
    "third_party/BearSSL/src/hash/dig_oid.c",
    "third_party/BearSSL/src/hash/dig_size.c",
    "third_party/BearSSL/src/hash/ghash_ctmul.c",
    "third_party/BearSSL/src/hash/ghash_ctmul32.c",
    "third_party/BearSSL/src/hash/ghash_ctmul64.c",
    "third_party/BearSSL/src/hash/ghash_pclmul.c",
    "third_party/BearSSL/src/hash/ghash_pwr8.c",
    "third_party/BearSSL/src/hash/md5.c",
    "third_party/BearSSL/src/hash/md5sha1.c",
    "third_party/BearSSL/src/hash/mgf1.c",
    "third_party/BearSSL/src/hash/multihash.c",
    "third_party/BearSSL/src/hash/sha1.c",
    "third_party/BearSSL/src/hash/sha2big.c",
    "third_party/BearSSL/src/hash/sha2small.c")
  add_files(
    "third_party/BearSSL/src/int/i15_add.c",
    "third_party/BearSSL/src/int/i15_bitlen.c",
    "third_party/BearSSL/src/int/i15_decmod.c",
    "third_party/BearSSL/src/int/i15_decode.c",
    "third_party/BearSSL/src/int/i15_decred.c",
    "third_party/BearSSL/src/int/i15_encode.c",
    "third_party/BearSSL/src/int/i15_fmont.c",
    "third_party/BearSSL/src/int/i15_iszero.c",
    "third_party/BearSSL/src/int/i15_moddiv.c",
    "third_party/BearSSL/src/int/i15_modpow.c",
    "third_party/BearSSL/src/int/i15_modpow2.c",
    "third_party/BearSSL/src/int/i15_montmul.c",
    "third_party/BearSSL/src/int/i15_mulacc.c",
    "third_party/BearSSL/src/int/i15_muladd.c",
    "third_party/BearSSL/src/int/i15_ninv15.c",
    "third_party/BearSSL/src/int/i15_reduce.c",
    "third_party/BearSSL/src/int/i15_rshift.c",
    "third_party/BearSSL/src/int/i15_sub.c",
    "third_party/BearSSL/src/int/i15_tmont.c",
    "third_party/BearSSL/src/int/i31_add.c",
    "third_party/BearSSL/src/int/i31_bitlen.c",
    "third_party/BearSSL/src/int/i31_decmod.c",
    "third_party/BearSSL/src/int/i31_decode.c",
    "third_party/BearSSL/src/int/i31_decred.c",
    "third_party/BearSSL/src/int/i31_encode.c",
    "third_party/BearSSL/src/int/i31_fmont.c",
    "third_party/BearSSL/src/int/i31_iszero.c",
    "third_party/BearSSL/src/int/i31_moddiv.c",
    "third_party/BearSSL/src/int/i31_modpow.c",
    "third_party/BearSSL/src/int/i31_modpow2.c",
    "third_party/BearSSL/src/int/i31_montmul.c",
    "third_party/BearSSL/src/int/i31_mulacc.c",
    "third_party/BearSSL/src/int/i31_muladd.c",
    "third_party/BearSSL/src/int/i31_ninv31.c",
    "third_party/BearSSL/src/int/i31_reduce.c",
    "third_party/BearSSL/src/int/i31_rshift.c",
    "third_party/BearSSL/src/int/i31_sub.c",
    "third_party/BearSSL/src/int/i31_tmont.c",
    "third_party/BearSSL/src/int/i32_add.c",
    "third_party/BearSSL/src/int/i32_bitlen.c",
    "third_party/BearSSL/src/int/i32_decmod.c",
    "third_party/BearSSL/src/int/i32_decode.c",
    "third_party/BearSSL/src/int/i32_decred.c",
    "third_party/BearSSL/src/int/i32_div32.c",
    "third_party/BearSSL/src/int/i32_encode.c",
    "third_party/BearSSL/src/int/i32_fmont.c",
    "third_party/BearSSL/src/int/i32_iszero.c",
    "third_party/BearSSL/src/int/i32_modpow.c",
    "third_party/BearSSL/src/int/i32_montmul.c",
    "third_party/BearSSL/src/int/i32_mulacc.c",
    "third_party/BearSSL/src/int/i32_muladd.c",
    "third_party/BearSSL/src/int/i32_ninv32.c",
    "third_party/BearSSL/src/int/i32_reduce.c",
    "third_party/BearSSL/src/int/i32_sub.c",
    "third_party/BearSSL/src/int/i32_tmont.c",
    "third_party/BearSSL/src/int/i62_modpow2.c")
  add_files(
    "third_party/BearSSL/src/kdf/hkdf.c",
    "third_party/BearSSL/src/kdf/shake.c")
  add_files(
    "third_party/BearSSL/src/mac/hmac.c",
    "third_party/BearSSL/src/mac/hmac_ct.c")
  add_files(
    "third_party/BearSSL/src/rand/aesctr_drbg.c",
    "third_party/BearSSL/src/rand/hmac_drbg.c",
    "third_party/BearSSL/src/rand/sysrng.c")
  add_files(
    "third_party/BearSSL/src/rsa/rsa_default_keygen.c",
    "third_party/BearSSL/src/rsa/rsa_default_modulus.c",
    "third_party/BearSSL/src/rsa/rsa_default_oaep_decrypt.c",
    "third_party/BearSSL/src/rsa/rsa_default_oaep_encrypt.c",
    "third_party/BearSSL/src/rsa/rsa_default_pkcs1_sign.c",
    "third_party/BearSSL/src/rsa/rsa_default_pkcs1_vrfy.c",
    "third_party/BearSSL/src/rsa/rsa_default_priv.c",
    "third_party/BearSSL/src/rsa/rsa_default_privexp.c",
    "third_party/BearSSL/src/rsa/rsa_default_pss_sign.c",
    "third_party/BearSSL/src/rsa/rsa_default_pss_vrfy.c",
    "third_party/BearSSL/src/rsa/rsa_default_pub.c",
    "third_party/BearSSL/src/rsa/rsa_default_pubexp.c",
    "third_party/BearSSL/src/rsa/rsa_i15_keygen.c",
    "third_party/BearSSL/src/rsa/rsa_i15_modulus.c",
    "third_party/BearSSL/src/rsa/rsa_i15_oaep_decrypt.c",
    "third_party/BearSSL/src/rsa/rsa_i15_oaep_encrypt.c",
    "third_party/BearSSL/src/rsa/rsa_i15_pkcs1_sign.c",
    "third_party/BearSSL/src/rsa/rsa_i15_pkcs1_vrfy.c",
    "third_party/BearSSL/src/rsa/rsa_i15_priv.c",
    "third_party/BearSSL/src/rsa/rsa_i15_privexp.c",
    "third_party/BearSSL/src/rsa/rsa_i15_pss_sign.c",
    "third_party/BearSSL/src/rsa/rsa_i15_pss_vrfy.c",
    "third_party/BearSSL/src/rsa/rsa_i15_pub.c",
    "third_party/BearSSL/src/rsa/rsa_i15_pubexp.c",
    "third_party/BearSSL/src/rsa/rsa_i31_keygen.c",
    "third_party/BearSSL/src/rsa/rsa_i31_keygen_inner.c",
    "third_party/BearSSL/src/rsa/rsa_i31_modulus.c",
    "third_party/BearSSL/src/rsa/rsa_i31_oaep_decrypt.c",
    "third_party/BearSSL/src/rsa/rsa_i31_oaep_encrypt.c",
    "third_party/BearSSL/src/rsa/rsa_i31_pkcs1_sign.c",
    "third_party/BearSSL/src/rsa/rsa_i31_pkcs1_vrfy.c",
    "third_party/BearSSL/src/rsa/rsa_i31_priv.c",
    "third_party/BearSSL/src/rsa/rsa_i31_privexp.c",
    "third_party/BearSSL/src/rsa/rsa_i31_pss_sign.c",
    "third_party/BearSSL/src/rsa/rsa_i31_pss_vrfy.c",
    "third_party/BearSSL/src/rsa/rsa_i31_pub.c",
    "third_party/BearSSL/src/rsa/rsa_i31_pubexp.c",
    "third_party/BearSSL/src/rsa/rsa_i32_oaep_decrypt.c",
    "third_party/BearSSL/src/rsa/rsa_i32_oaep_encrypt.c",
    "third_party/BearSSL/src/rsa/rsa_i32_pkcs1_sign.c",
    "third_party/BearSSL/src/rsa/rsa_i32_pkcs1_vrfy.c",
    "third_party/BearSSL/src/rsa/rsa_i32_priv.c",
    "third_party/BearSSL/src/rsa/rsa_i32_pss_sign.c",
    "third_party/BearSSL/src/rsa/rsa_i32_pss_vrfy.c",
    "third_party/BearSSL/src/rsa/rsa_i32_pub.c",
    "third_party/BearSSL/src/rsa/rsa_i62_keygen.c",
    "third_party/BearSSL/src/rsa/rsa_i62_oaep_decrypt.c",
    "third_party/BearSSL/src/rsa/rsa_i62_oaep_encrypt.c",
    "third_party/BearSSL/src/rsa/rsa_i62_pkcs1_sign.c",
    "third_party/BearSSL/src/rsa/rsa_i62_pkcs1_vrfy.c",
    "third_party/BearSSL/src/rsa/rsa_i62_priv.c",
    "third_party/BearSSL/src/rsa/rsa_i62_pss_sign.c",
    "third_party/BearSSL/src/rsa/rsa_i62_pss_vrfy.c",
    "third_party/BearSSL/src/rsa/rsa_i62_pub.c",
    "third_party/BearSSL/src/rsa/rsa_oaep_pad.c",
    "third_party/BearSSL/src/rsa/rsa_oaep_unpad.c",
    "third_party/BearSSL/src/rsa/rsa_pkcs1_sig_pad.c",
    "third_party/BearSSL/src/rsa/rsa_pkcs1_sig_unpad.c",
    "third_party/BearSSL/src/rsa/rsa_pss_sig_pad.c",
    "third_party/BearSSL/src/rsa/rsa_pss_sig_unpad.c",
    "third_party/BearSSL/src/rsa/rsa_ssl_decrypt.c")
  add_files(
    "third_party/BearSSL/src/ssl/prf.c",
    "third_party/BearSSL/src/ssl/prf_md5sha1.c",
    "third_party/BearSSL/src/ssl/prf_sha256.c",
    "third_party/BearSSL/src/ssl/prf_sha384.c",
    "third_party/BearSSL/src/ssl/ssl_ccert_single_ec.c",
    "third_party/BearSSL/src/ssl/ssl_ccert_single_rsa.c",
    "third_party/BearSSL/src/ssl/ssl_client.c",
    "third_party/BearSSL/src/ssl/ssl_client_default_rsapub.c",
    "third_party/BearSSL/src/ssl/ssl_client_full.c",
    "third_party/BearSSL/src/ssl/ssl_engine.c",
    "third_party/BearSSL/src/ssl/ssl_engine_default_aescbc.c",
    "third_party/BearSSL/src/ssl/ssl_engine_default_aesccm.c",
    "third_party/BearSSL/src/ssl/ssl_engine_default_aesgcm.c",
    "third_party/BearSSL/src/ssl/ssl_engine_default_chapol.c",
    "third_party/BearSSL/src/ssl/ssl_engine_default_descbc.c",
    "third_party/BearSSL/src/ssl/ssl_engine_default_ec.c",
    "third_party/BearSSL/src/ssl/ssl_engine_default_ecdsa.c",
    "third_party/BearSSL/src/ssl/ssl_engine_default_rsavrfy.c",
    "third_party/BearSSL/src/ssl/ssl_hashes.c",
    "third_party/BearSSL/src/ssl/ssl_hs_client.c",
    "third_party/BearSSL/src/ssl/ssl_hs_server.c",
    "third_party/BearSSL/src/ssl/ssl_io.c",
    "third_party/BearSSL/src/ssl/ssl_keyexport.c",
    "third_party/BearSSL/src/ssl/ssl_lru.c",
    "third_party/BearSSL/src/ssl/ssl_rec_cbc.c",
    "third_party/BearSSL/src/ssl/ssl_rec_ccm.c",
    "third_party/BearSSL/src/ssl/ssl_rec_chapol.c",
    "third_party/BearSSL/src/ssl/ssl_rec_gcm.c",
    "third_party/BearSSL/src/ssl/ssl_scert_single_ec.c",
    "third_party/BearSSL/src/ssl/ssl_scert_single_rsa.c",
    "third_party/BearSSL/src/ssl/ssl_server.c",
    "third_party/BearSSL/src/ssl/ssl_server_full_ec.c",
    "third_party/BearSSL/src/ssl/ssl_server_full_rsa.c",
    "third_party/BearSSL/src/ssl/ssl_server_mine2c.c",
    "third_party/BearSSL/src/ssl/ssl_server_mine2g.c",
    "third_party/BearSSL/src/ssl/ssl_server_minf2c.c",
    "third_party/BearSSL/src/ssl/ssl_server_minf2g.c",
    "third_party/BearSSL/src/ssl/ssl_server_minr2g.c",
    "third_party/BearSSL/src/ssl/ssl_server_minu2g.c",
    "third_party/BearSSL/src/ssl/ssl_server_minv2g.c")
  add_files(
    "third_party/BearSSL/src/symcipher/aes_big_cbcdec.c",
    "third_party/BearSSL/src/symcipher/aes_big_cbcenc.c",
    "third_party/BearSSL/src/symcipher/aes_big_ctr.c",
    "third_party/BearSSL/src/symcipher/aes_big_ctrcbc.c",
    "third_party/BearSSL/src/symcipher/aes_big_dec.c",
    "third_party/BearSSL/src/symcipher/aes_big_enc.c",
    "third_party/BearSSL/src/symcipher/aes_common.c",
    "third_party/BearSSL/src/symcipher/aes_ct.c",
    "third_party/BearSSL/src/symcipher/aes_ct64.c",
    "third_party/BearSSL/src/symcipher/aes_ct64_cbcdec.c",
    "third_party/BearSSL/src/symcipher/aes_ct64_cbcenc.c",
    "third_party/BearSSL/src/symcipher/aes_ct64_ctr.c",
    "third_party/BearSSL/src/symcipher/aes_ct64_ctrcbc.c",
    "third_party/BearSSL/src/symcipher/aes_ct64_dec.c",
    "third_party/BearSSL/src/symcipher/aes_ct64_enc.c",
    "third_party/BearSSL/src/symcipher/aes_ct_cbcdec.c",
    "third_party/BearSSL/src/symcipher/aes_ct_cbcenc.c",
    "third_party/BearSSL/src/symcipher/aes_ct_ctr.c",
    "third_party/BearSSL/src/symcipher/aes_ct_ctrcbc.c",
    "third_party/BearSSL/src/symcipher/aes_ct_dec.c",
    "third_party/BearSSL/src/symcipher/aes_ct_enc.c",
    "third_party/BearSSL/src/symcipher/aes_pwr8.c",
    "third_party/BearSSL/src/symcipher/aes_pwr8_cbcdec.c",
    "third_party/BearSSL/src/symcipher/aes_pwr8_cbcenc.c",
    "third_party/BearSSL/src/symcipher/aes_pwr8_ctr.c",
    "third_party/BearSSL/src/symcipher/aes_pwr8_ctrcbc.c",
    "third_party/BearSSL/src/symcipher/aes_small_cbcdec.c",
    "third_party/BearSSL/src/symcipher/aes_small_cbcenc.c",
    "third_party/BearSSL/src/symcipher/aes_small_ctr.c",
    "third_party/BearSSL/src/symcipher/aes_small_ctrcbc.c",
    "third_party/BearSSL/src/symcipher/aes_small_dec.c",
    "third_party/BearSSL/src/symcipher/aes_small_enc.c",
    "third_party/BearSSL/src/symcipher/aes_x86ni.c",
    "third_party/BearSSL/src/symcipher/aes_x86ni_cbcdec.c",
    "third_party/BearSSL/src/symcipher/aes_x86ni_cbcenc.c",
    "third_party/BearSSL/src/symcipher/aes_x86ni_ctr.c",
    "third_party/BearSSL/src/symcipher/aes_x86ni_ctrcbc.c",
    "third_party/BearSSL/src/symcipher/chacha20_ct.c",
    "third_party/BearSSL/src/symcipher/chacha20_sse2.c",
    "third_party/BearSSL/src/symcipher/des_ct.c",
    "third_party/BearSSL/src/symcipher/des_ct_cbcdec.c",
    "third_party/BearSSL/src/symcipher/des_ct_cbcenc.c",
    "third_party/BearSSL/src/symcipher/des_support.c",
    "third_party/BearSSL/src/symcipher/des_tab.c",
    "third_party/BearSSL/src/symcipher/des_tab_cbcdec.c",
    "third_party/BearSSL/src/symcipher/des_tab_cbcenc.c",
    "third_party/BearSSL/src/symcipher/poly1305_ctmul.c",
    "third_party/BearSSL/src/symcipher/poly1305_ctmul32.c",
    "third_party/BearSSL/src/symcipher/poly1305_ctmulq.c",
    "third_party/BearSSL/src/symcipher/poly1305_i15.c")
  add_files(
    "third_party/BearSSL/src/x509/asn1enc.c",
    "third_party/BearSSL/src/x509/encode_ec_pk8der.c",
    "third_party/BearSSL/src/x509/encode_ec_rawder.c",
    "third_party/BearSSL/src/x509/encode_rsa_pk8der.c",
    "third_party/BearSSL/src/x509/encode_rsa_rawder.c",
    "third_party/BearSSL/src/x509/skey_decoder.c")
  add_files(
    "third_party/BearSSL/src/x509/x509_decoder.c",
    "third_party/BearSSL/src/x509/x509_knownkey.c",
    --"third_party/BearSSL/src/x509/x509_minimal.c",
    "third_party/BearSSL/src/x509/x509_minimal_full.c")
  -- Wrapper around x509_minimal.c that uses our time implementation from sntp.
  add_files("x509_minimal_wrapper.c")

compartment("TCPIP")
  set_default(false)
  add_deps("freestanding", "string", "message_queue_library", "event_group", "stdio", "cxxrt")
  add_cflags("-Wno-error=int-conversion", "-Wno-error=cheri-provenance", "-Wno-error=pointer-integer-compare", { force = true})
  add_defines("CHERIOT_CUSTOM_DEFAULT_MALLOC_CAPABILITY")
  add_defines("CHERIOT_EXPOSE_FREERTOS_SEMAPHORE")
  on_load(function(target)
    target:add('options', "IPv6")
    local IPv6 = get_config("IPv6")
    target:add("defines", "CHERIOT_RTOS_OPTION_IPv6=" .. tostring(IPv6))
    target:add("files", {
            "third_party/freertos-plus-tcp/source/FreeRTOS_DHCPv6.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_TCP_State_Handling_IPv6.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_TCP_IP_IPv6.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_IPv6.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_IPv6_Sockets.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_IPv6_Utils.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_TCP_Transmission_IPv6.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_TCP_Utils_IPv6.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_UDP_IPv6.c"
    })
  end)
  add_includedirs("include", ".", "third_party/freertos-plus-tcp/source/include")
  add_includedirs("third_party/freertos")
  add_includedirs(path.join(sdkdir, "include/FreeRTOS-Compat"))
  add_files("third_party/freertos/list.c")
  add_files("externs.c")
  add_files("FreeRTOS_IP_wrapper.c")
  add_files("BufferManagement.cc")
  add_files("driver_adaptor.cc")
  add_files("network_wrapper.cc")
  add_files("startup.cc")
  add_files(
            "third_party/freertos-plus-tcp/source/FreeRTOS_ARP.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_BitConfig.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_DHCP.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_DNS.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_DNS_Cache.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_DNS_Callback.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_DNS_Networking.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_DNS_Parser.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_ICMP.c",
            -- Included via a wrapper that statically creates the thread.
            --"third_party/freertos-plus-tcp/source/FreeRTOS_IP.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_IP_Timers.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_IP_Utils.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_IPv4.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_IPv4_Sockets.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_IPv4_Utils.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_ND.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_RA.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_Routing.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_Sockets.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_Stream_Buffer.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_TCP_IP.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_TCP_IP_IPv4.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_TCP_Reception.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_TCP_State_Handling.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_TCP_State_Handling_IPv4.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_TCP_Transmission.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_TCP_Transmission_IPv4.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_TCP_Utils.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_TCP_Utils_IPv4.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_TCP_WIN.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_Tiny_TCP.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_UDP_IP.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_UDP_IPv4.c"
            )

compartment("NetAPI")
  set_default(false)
  add_includedirs("include")
  add_deps("freestanding", "TCPIP")
  add_files("NetAPI.cc")
  on_load(function(target)
    target:add('options', "IPv6")
    local IPv6 = get_config("IPv6")
    target:add("defines", "CHERIOT_RTOS_OPTION_IPv6=" .. tostring(IPv6))
  end)

compartment("SNTP")
  set_default(false)
  add_deps("freestanding", "NetAPI")
  add_files("sntp.cc")
  add_includedirs(".", "include", "third_party/coreSNTP/source/include")
  add_defines("CHERIOT_CUSTOM_DEFAULT_MALLOC_CAPABILITY")
  add_files("third_party/coreSNTP/source/core_sntp_client.c",
            "third_party/coreSNTP/source/core_sntp_serializer.c")

compartment("test")
  set_default(false)
  add_includedirs("include")
  add_deps("freestanding", "TCPIP", "NetAPI", "TLS")
  add_files("test.cc")
  on_load(function(target)
    target:add('options', "IPv6")
    local IPv6 = get_config("IPv6")
    target:add("defines", "CHERIOT_RTOS_OPTION_IPv6=" .. tostring(IPv6))
  end)

firmware("toy_network")
    set_policy("build.warning", true)
    add_deps("TCPIP", "Firewall", "NetAPI", "SNTP", "test", "atomic8", "time_helpers", "debug")
    on_load(function(target)
        target:values_set("board", "$(board)")
        target:values_set("threads", {
            {
                compartment = "test",
                priority = 1,
                entry_point = "test_network",
                -- TLS requires *huge* stacks!
                stack_size = 8160,
                trusted_stack_frames = 6
            },
            {
                compartment = "TCPIP",
                priority = 1,
                entry_point = "ip_thread_entry",
                stack_size = 0xe00,
                trusted_stack_frames = 5
            },
            {
                compartment = "Firewall",
                -- Higher priority, this will be back-pressured by the message
                -- queue if the network stack can't keep up, but we want
                -- packets to arrive immediately.
                priority = 2,
                entry_point = "ethernet_run_driver",
                stack_size = 0x1000,
                trusted_stack_frames = 5
            }
        }, {expand = false})
    end)

