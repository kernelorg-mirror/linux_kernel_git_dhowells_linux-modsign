#
# Makefile for cryptographic keys
#

obj-$(CONFIG_CRYPTO_KEY_TYPE) += crypto_keys.o
crypto_keys-y := crypto_type.o crypto_verify.o

obj-$(CONFIG_CRYPTO_KEY_PUBLIC_KEY_SUBTYPE) += public_key.o
obj-$(CONFIG_CRYPTO_KEY_PKEY_ALGO_RSA) += crypto_rsa.o
obj-$(CONFIG_PGP_LIBRARY) += pgp_library.o
