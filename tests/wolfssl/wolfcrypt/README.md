# wolfCrypt Tests for CHERIoT

wolfCrypt is the cryptography library at the core of wolfSSL.
This directory contains a combined project that can run the wolfCrypt test suite, benchmark suite, or both.

By default both run: the test suite first, then the benchmark.

## Building and running

```bash
cd tests/wolfssl/wolfcrypt
xmake config --sdk=/cheriot-tools --board=sonata-1.3 -m release
xmake
cp ./build/cheriot/cheriot/release/firmware.uf2 /mnt/SONATA/
```

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `run_test` | `true` | Run the wolfCrypt test suite |
| `run_bench` | `true` | Run the wolfCrypt benchmark suite |
| `heartbeat` | `false` | Print elapsed time every 5 s (useful on long runs) |
| `board` | `sonata-1.3` | Target board (`sonata-1.3`, `sail`, etc.) |

Examples:

```bash
# Test only
xmake config --sdk=/cheriot-tools --board=sonata-1.3 -m release --run_bench=n

# Benchmark only
xmake config --sdk=/cheriot-tools --board=sonata-1.3 -m release --run_test=n

# Both with heartbeat (Indicates that the board is still alive on long runs)
xmake config --sdk=/cheriot-tools --board=sonata-1.3 -m release --heartbeat=y
```

## Expected output

### Test suite

The test suite takes around 10 minutes on SONATA.

```
WolfCrypt: === wolfCrypt test suite ===
------------------------------------------------------------------------------
 wolfSSL version 5.9.1
------------------------------------------------------------------------------
macro    test passed!
error    test passed!
MEMORY   test passed!
base64   test passed!
asn      test passed!
SHA      test passed!
SHA-256  test passed!
SHA-384  test passed!
SHA-512  test passed!
SHA-512/224  test passed!
SHA-512/256  test passed!
RANDOM   test passed!
Hash     test passed!
HMAC-SHA test passed!
HMAC-SHA256 test passed!
HMAC-SHA384 test passed!
HMAC-SHA512 test passed!
HMAC-KDF    test passed!
PRF         test passed!
TLSv1.3 KDF test passed!
GMAC     test passed!
Chacha   test passed!
POLY1305 test passed!
ChaCha20-Poly1305 AEAD test passed!
AES      test passed!
AES192   test passed!
AES256   test passed!
AES-CBC  test passed!
AES-GCM  test passed!
RSA      test passed!
DH       test passed!
ECC      test passed!
ECC buffer test passed!
logging  test passed!
time     test passed!
mutex    test passed!
Test complete
WolfCrypt: === ALL TESTS PASSED ===
```

### Benchmark suite

```
WolfCrypt: === wolfCrypt benchmark suite ===
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
RNG SHA-256 DRBG         175.0 KiB took 1.101 seconds, 158.906 KiB/s
AES-128-CBC-enc          25.0 KiB took 4.329 seconds, 5.775 KiB/s
AES-128-CBC-dec          25.0 KiB took 4.313 seconds, 5.796 KiB/s
AES-192-CBC-enc          25.0 KiB took 5.191 seconds, 4.816 KiB/s
AES-192-CBC-dec          25.0 KiB took 5.152 seconds, 4.852 KiB/s
AES-256-CBC-enc          25.0 KiB took 6.059 seconds, 4.126 KiB/s
AES-256-CBC-dec          25.0 KiB took 5.988 seconds, 4.175 KiB/s
AES-128-GCM-enc          25.0 KiB took 5.935 seconds, 4.212 KiB/s
AES-128-GCM-dec          25.0 KiB took 5.933 seconds, 4.213 KiB/s
AES-192-GCM-enc          25.0 KiB took 6.848 seconds, 3.651 KiB/s
AES-192-GCM-dec          25.0 KiB took 6.848 seconds, 3.651 KiB/s
AES-256-GCM-enc          25.0 KiB took 7.747 seconds, 3.227 KiB/s
AES-256-GCM-dec          25.0 KiB took 7.749 seconds, 3.226 KiB/s
AES-128-GCM-enc-no_AAD   25.0 KiB took 5.912 seconds, 4.229 KiB/s
AES-128-GCM-dec-no_AAD   25.0 KiB took 5.910 seconds, 4.230 KiB/s
AES-192-GCM-enc-no_AAD   25.0 KiB took 6.824 seconds, 3.664 KiB/s
AES-192-GCM-dec-no_AAD   25.0 KiB took 6.825 seconds, 3.663 KiB/s
AES-256-GCM-enc-no_AAD   25.0 KiB took 7.723 seconds, 3.237 KiB/s
AES-256-GCM-dec-no_AAD   25.0 KiB took 7.724 seconds, 3.237 KiB/s
GMAC Small               25.0 KiB took 1.574 seconds, 15.881 KiB/s
CHACHA                   700.0 KiB took 1.002 seconds, 698.864 KiB/s
CHA-POLY                 350.0 KiB took 1.040 seconds, 336.554 KiB/s
POLY1305                 1.0 MiB took 1.009 seconds, 1.210 MiB/s
SHA                      975.0 KiB took 1.018 seconds, 957.817 KiB/s
SHA-256                  525.0 KiB took 1.041 seconds, 504.415 KiB/s
SHA-384                  150.0 KiB took 1.151 seconds, 130.289 KiB/s
SHA-512                  150.0 KiB took 1.150 seconds, 130.437 KiB/s
SHA-512/224              150.0 KiB took 1.150 seconds, 130.455 KiB/s
SHA-512/256              150.0 KiB took 1.154 seconds, 129.972 KiB/s
HMAC-SHA                 950.0 KiB took 1.004 seconds, 946.033 KiB/s
HMAC-SHA256              500.0 KiB took 1.003 seconds, 498.398 KiB/s
HMAC-SHA384              150.0 KiB took 1.167 seconds, 128.587 KiB/s
HMAC-SHA512              150.0 KiB took 1.166 seconds, 128.596 KiB/s
RSA     2048   public         8 ops took 1.038 sec, avg 129.761 ms, 7.706 ops/sec
RSA     2048  private         2 ops took 15.161 sec, avg 7580.444 ms, 0.132 ops/sec
DH      2048  key gen         1 ops took 3.181 sec, avg 3181.317 ms, 0.314 ops/sec
DH      2048    agree         2 ops took 6.363 sec, avg 3181.502 ms, 0.314 ops/sec
ECC   [      SECP256R1]   256  key gen         2 ops took 1.071 sec, avg 535.416 ms, 1.868 ops/sec
ECDHE [      SECP256R1]   256    agree         2 ops took 1.068 sec, avg 534.194 ms, 1.872 ops/sec
ECDSA [      SECP256R1]   256     sign         2 ops took 1.179 sec, avg 589.603 ms, 1.696 ops/sec
ECDSA [      SECP256R1]   256   verify         2 ops took 2.161 sec, avg 1080.369 ms, 0.926 ops/sec
RNG      256 SHA256 Init/Free     86 ops took 1.007 sec, avg 11.709 ms, 85.403 ops/sec
Benchmark complete
WolfCrypt: === BENCHMARK COMPLETE ===
```
