#
# Makefile for cryptographic keys
#

obj-$(CONFIG_CRYPTO_KEY_TYPE) += crypto_keys.o
crypto_keys-y := crypto_type.o crypto_verify.o

obj-$(CONFIG_CRYPTO_KEY_PUBLIC_KEY_SUBTYPE) += public_key.o
obj-$(CONFIG_CRYPTO_KEY_PKEY_ALGO_RSA) += crypto_rsa.o
obj-$(CONFIG_PGP_LIBRARY) += pgp_library.o
obj-$(CONFIG_PGP_PRELOAD) += pgp_preload.o

obj-$(CONFIG_CRYPTO_KEY_PGP_PARSER) += pgp_key_parser.o
pgp_key_parser-y := \
	pgp_public_key.o \
	pgp_sig_parser.o \
	pgp_sig_verify.o

#
# X.509 Certificate handling
#
obj-$(CONFIG_CRYPTO_KEY_X509_PARSER) += x509_key_parser.o
x509_key_parser-y := \
	x509-asn1.o \
	x509_rsakey-asn1.o \
	x509_cert_parser.o \
	x509_public_key.o

$(obj)/x509_cert_parser.o: $(obj)/x509-asn1.h $(obj)/x509_rsakey-asn1.h
$(obj)/x509-asn1.o: $(obj)/x509-asn1.c $(obj)/x509-asn1.h
$(obj)/x509_rsakey-asn1.o: $(obj)/x509_rsakey-asn1.c $(obj)/x509_rsakey-asn1.h

clean-files	+= x509-asn1.c x509-asn1.h
clean-files	+= x509_rsakey-asn1.c x509_rsakey-asn1.h
