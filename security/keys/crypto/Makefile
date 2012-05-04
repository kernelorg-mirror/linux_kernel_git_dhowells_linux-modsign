#
# Makefile for cryptographic keys
#

obj-$(CONFIG_CRYPTO_KEY_TYPE) += crypto_keys.o
crypto_keys-y := crypto_type.o crypto_verify.o

obj-$(CONFIG_CRYPTO_KEY_PUBLIC_KEY_SUBTYPE) += public_key.o
obj-$(CONFIG_CRYPTO_KEY_PKEY_ALGO_RSA) += crypto_rsa.o
obj-$(CONFIG_PGP_LIBRARY) += pgp_library.o

obj-$(CONFIG_CRYPTO_KEY_PGP_PARSER) += pgp_parser.o
pgp_parser-y := \
	pgp_key_parser.o \
	pgp_sig_parser.o \
	pgp_pubkey_sig.o
