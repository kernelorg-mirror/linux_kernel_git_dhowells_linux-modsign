/* PKCS#7 crypto data parser internal definitions
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define kenter(FMT, ...) \
	pr_devel("==> %s("FMT")\n", __func__, ##__VA_ARGS__)
#define kleave(FMT, ...) \
	pr_devel("<== %s()"FMT"\n", __func__, ##__VA_ARGS__)

struct pkcs7_signature {
	struct x509_certificate *certs;	/* Certificate list */
	struct x509_certificate *crl;	/* Revocation list */
};

/*
 * pkcs7_parser.c
 */
extern struct pkcs7_signature *pkcs7_parse_signature(const void *data,
						     size_t datalen);
extern void pkcs7_free_signature(struct pkcs7_signature *pkcs7);

/*
 * pkcs7_sig_verify.c
 */
extern struct crypto_sig_verify_context *pkcs7_do_verify_sig_begin(
	struct key *crypto_key, const u8 *sigdata, size_t siglen);
