/* PKCS#7 parser
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */
#define DEBUG
#define pr_fmt(fmt) "PKCS7: "fmt
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/oid_registry.h>
#include "public_key.h"
#include "x509_parser.h"
#include "pkcs7_parser.h"
#include "pkcs7-asn1.h"

struct pkcs7_parse_context {
	struct public_key *pub;			/* Public key definition */
	struct pkcs7_signature	*sig;		/* Signature being constructed */
	struct x509_certificate *certs;		/* Certificate cache */
	struct x509_certificate **ppcerts;
	unsigned long	data;			/* Start of data */
	enum OID	last_oid;		/* Last OID encountered */
	enum OID	algo_oid;		/* Algorithm OID */
	unsigned char	nr_mpi;			/* Number of MPIs stored */
	int		namesize;		/* Usage of namebuffer */
	char		namebuffer[256];	/* Name building buffer */
};

/*
 * Free a PKCS#7 signature
 */
void pkcs7_free_signature(struct pkcs7_signature *pkcs7)
{
	struct x509_certificate *cert;

	if (pkcs7) {
		while (pkcs7->certs) {
			cert = pkcs7->certs;
			pkcs7->certs = cert->next;
			x509_free_certificate(cert);
		}
		while (pkcs7->crl) {
			cert = pkcs7->certs;
			pkcs7->certs = cert->next;
			x509_free_certificate(cert);
		}
		kfree(pkcs7);
	}
}

/*
 * Parse a PKCS#7 signature
 */
struct pkcs7_signature *pkcs7_parse_signature(const void *data, size_t datalen)
{
	struct pkcs7_parse_context *ctx;
	struct pkcs7_signature *sig;	
	long ret;

	ret = -ENOMEM;
	sig = kzalloc(sizeof(struct pkcs7_signature), GFP_KERNEL);
	if (!sig)
		goto error_no_sig;
	ctx = kzalloc(sizeof(struct pkcs7_parse_context), GFP_KERNEL);
	if (!ctx)
		goto error_no_ctx;

	ctx->sig = sig;
	ctx->data = (unsigned long)data;
	ctx->ppcerts = &ctx->certs;

	/* Attempt to decode the signature */
	ret = asn1_ber_decoder(&pkcs7_decoder, ctx, data, datalen);
	if (ret < 0)
		goto error_decode;

	while (ctx->certs) {
		struct x509_certificate *cert = ctx->certs;
		ctx->certs = cert->next;
		x509_free_certificate(cert);
	}
	kfree(ctx);
	return sig;

error_decode:
	kfree(ctx);
error_no_ctx:
	pkcs7_free_signature(sig);
error_no_sig:
	return ERR_PTR(ret);
}

/*
 * Note an OID when we find one for later processing when we know how
 * to interpret it.
 */
int pkcs7_note_OID(void *context, size_t hdrlen,
		   unsigned char tag,
		   const void *value, size_t vlen)
{
	struct pkcs7_parse_context *ctx = context;

	ctx->last_oid = look_up_OID(value, vlen);
	if (ctx->last_oid == OID__NR) {
		char buffer[50];
		sprint_oid(value, vlen, buffer, sizeof(buffer));
		printk("PKCS7: Unknown OID: [%zu] %s\n",
		       (unsigned long)value - ctx->data, buffer);
	}
	return 0;
}

/*
 * Extract a certificate and store it in the cache.
 */
int pkcs7_extract_cert(void *context, size_t hdrlen,
		       unsigned char tag,
		       const void *value, size_t vlen)
{
	struct pkcs7_parse_context *ctx = context;
	struct x509_certificate *cert;

	if (tag != ((ASN1_UNIV << 6) | ASN1_CONS_BIT | ASN1_SEQ)) {
		pr_debug("Cert began with tag %02x at %zu\n",
			 tag, (unsigned long)ctx - ctx->data);
		return -EBADMSG;
	}

	//pr_debug("Try to parse cert %02x:%zu at %zu (-hdr %zu)\n",
	//	 tag, vlen, (unsigned long)ctx - ctx->data, hdrlen);

	/* We have to correct for the header so that the X.509 parser can start
	 * from the beginning.  Note that since X.509 stipulates DER, there
	 * probably shouldn't be an EOC trailer - but it is in PKCS#7 (which
	 * stipulates BER).
	 */
	value -= hdrlen;
	vlen += hdrlen;

	if (((u8*)value)[1] == 0x80)
		vlen += 2; /* Indefinite length - there should be an EOC */

	cert = x509_cert_parse(value, vlen);
	if (IS_ERR(cert))
		return PTR_ERR(cert);

	pr_debug("Got cert for %s\n", cert->subject);
	pr_debug("- fingerprint %s\n", cert->fingerprint);

	*ctx->ppcerts = cert;
	ctx->ppcerts = &cert->next;
	return 0;
}
