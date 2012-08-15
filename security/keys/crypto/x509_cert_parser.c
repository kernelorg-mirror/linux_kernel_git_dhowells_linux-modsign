/* X.509 certificate parser
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */
#undef DEBUG
#define pr_fmt(fmt) "X.509: "fmt
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/oid_registry.h>
#include "public_key.h"
#include "x509_parser.h"
#include "x509-asn1.h"
#include "x509_rsakey-asn1.h"

struct x509_parse_context {
	struct x509_certificate	*cert;		/* Certificate being constructed */
	unsigned long	data;			/* Start of data */
	const void	*cert_start;		/* Start of cert content */
	const void	*key;			/* Key data */
	size_t		key_size;		/* Size of key data */
	enum OID	last_oid;		/* Last OID encountered */
	enum OID	algo_oid;		/* Algorithm OID */
	unsigned char	nr_mpi;			/* Number of MPIs stored */
	int		namesize;		/* Usage of namebuffer */
	char		namebuffer[256];	/* Name building buffer */
};

/*
 * Free an X.509 certificate
 */
void x509_free_certificate(struct x509_certificate *cert)
{
	if (cert) {
		public_key_destroy(cert->pub);
		kfree(cert->serial);
		kfree(cert->issuer);
		kfree(cert->subject);
		kfree(cert->fingerprint);
		kfree(cert->authority);
		kfree(cert);
	}
}

/*
 * Parse an X.509 certificate
 */
struct x509_certificate *x509_cert_parse(const void *data, size_t datalen)
{
	struct x509_certificate *cert;
	struct x509_parse_context *ctx;
	long ret;

	ret = -ENOMEM;
	cert = kzalloc(sizeof(struct x509_certificate), GFP_KERNEL);
	if (!cert)
		goto error_no_cert;
	cert->pub = kzalloc(sizeof(struct public_key), GFP_KERNEL);
	if (!cert->pub)
		goto error_no_ctx;
	ctx = kzalloc(sizeof(struct x509_parse_context), GFP_KERNEL);
	if (!ctx)
		goto error_no_ctx;

	ctx->cert = cert;
	ctx->data = (unsigned long)data;

	/* Attempt to decode the certificate */
	ret = asn1_ber_decoder(&x509_decoder, ctx, data, datalen);
	if (ret < 0)
		goto error_decode;

	/* Decode the public key */
	ret = asn1_ber_decoder(&x509_rsakey_decoder, ctx,
			       ctx->key, ctx->key_size);
	if (ret < 0)
		goto error_decode;

	kfree(ctx);
	return cert;

error_decode:
	kfree(ctx);
error_no_ctx:
	x509_free_certificate(cert);
error_no_cert:
	return ERR_PTR(ret);
}

/*
 * Note an OID when we find one for later processing when we know how
 * to interpret it.
 */
int x509_note_OID(void *context, size_t hdrlen,
	     unsigned char tag,
	     const void *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;

	ctx->last_oid = look_up_OID(value, vlen);
	if (ctx->last_oid == OID__NR) {
		char buffer[50];
		sprint_oid(value, vlen, buffer, sizeof(buffer));
		printk("X.509: Unknown OID: [%zu] %s: %d\n",
		       (unsigned long)value - ctx->data, buffer, ctx->last_oid);
	}
	return 0;
}

/*
 * Save the position of the TBS data so that we can check the signature over it
 * later.
 */
int x509_note_tbs_certificate(void *context, size_t hdrlen,
			      unsigned char tag,
			      const void *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;

	pr_debug("x509_note_tbs_certificate(,%02x,%ld,%zu)!\n",
		 tag, (unsigned long)value - ctx->data, vlen);

	ctx->cert->tbs = value;
	ctx->cert->tbs_size = vlen;
	return 0;
}

/*
 * Note the start position of the certificate content with respect to the TBS
 * data and use this to compute the length of the TBS header which is needed
 * for the signature check.
 */
int x509_note_cert_start(void *context, size_t hdrlen,
			 unsigned char tag,
			 const void *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	ptrdiff_t hdrsize;

	pr_debug("x509_note_cert_start(,%02x,%ld,%zu)!\n",
		 tag, (unsigned long)value - ctx->data, vlen);

	hdrsize = ctx->cert->tbs - value;
	ctx->cert->tbs = value;
	ctx->cert->tbs_size += hdrsize;
	return 0;
}

/*
 * Record the public key algorithm
 */
int x509_note_pkey_algo(void *context, size_t hdrlen,
			unsigned char tag,
			const void *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;

	pr_debug("PubKey Algo: %u\n", ctx->last_oid);

	switch (ctx->last_oid) {
	case OID_md2WithRSAEncryption:
	case OID_md3WithRSAEncryption:
	default:
		return -ENOPKG; /* Unsupported combination */

	case OID_md4WithRSAEncryption:
		ctx->cert->sig_hash_algo = PKEY_HASH_MD5;
		ctx->cert->sig_pkey_algo = PKEY_ALGO_RSA;
		break;

	case OID_sha1WithRSAEncryption:
		ctx->cert->sig_hash_algo = PKEY_HASH_SHA1;
		ctx->cert->sig_pkey_algo = PKEY_ALGO_RSA;
		break;

	case OID_sha256WithRSAEncryption:
		ctx->cert->sig_hash_algo = PKEY_HASH_SHA256;
		ctx->cert->sig_pkey_algo = PKEY_ALGO_RSA;
		break;

	case OID_sha384WithRSAEncryption:
		ctx->cert->sig_hash_algo = PKEY_HASH_SHA384;
		ctx->cert->sig_pkey_algo = PKEY_ALGO_RSA;
		break;

	case OID_sha512WithRSAEncryption:
		ctx->cert->sig_hash_algo = PKEY_HASH_SHA512;
		ctx->cert->sig_pkey_algo = PKEY_ALGO_RSA;
		break;

	case OID_sha224WithRSAEncryption:
		ctx->cert->sig_hash_algo = PKEY_HASH_SHA224;
		ctx->cert->sig_pkey_algo = PKEY_ALGO_RSA;
		break;
	}

	ctx->algo_oid = ctx->last_oid;
	return 0;
}

/*
 * Note the whereabouts and type of the signature.
 */
int x509_note_signature(void *context, size_t hdrlen,
			unsigned char tag,
			const void *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;

	pr_debug("Signature type: %u size %zu\n", ctx->last_oid, vlen);

	if (ctx->last_oid != ctx->algo_oid) {
		pr_warn("X.509: Got cert with pkey (%u) and sig (%u) algorithm OIDs\n",
			ctx->algo_oid, ctx->last_oid);
		return -EINVAL;
	}

	ctx->cert->sig = value;
	ctx->cert->sig_size = vlen;
	return 0;
}

/*
 * Extract name segments into the assembly buffer and tag them with prefixes
 * appropriate to the attribute OID.
 */
int x509_extract_name_segment(void *context, size_t hdrlen,
			      unsigned char tag,
			      const void *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	const char *prefix;
	char pbuf[4];

	switch (ctx->last_oid) {
	case OID_commonName:		prefix = "CN";	break;
	case OID_surname:		prefix = "S";	break;
	case OID_countryName:		prefix = "C";	break;
	case OID_locality:		prefix = "L";	break;
	case OID_stateOrProvinceName:	prefix = "ST";	break;
	case OID_organizationName:	prefix = "O";	break;
	case OID_organizationUnitName:	prefix = "OU";	break;
	case OID_title:			prefix = "T";	break;
	case OID_name:			prefix = "N";	break;
	case OID_givenName:		prefix = "G";	break;
	case OID_initials:		prefix = "I";	break;
	case OID_generationalQualifier:	prefix = "GQ";	break;
	default:
		sprintf(pbuf, "?%u", ctx->last_oid);
		prefix = pbuf;
		break;
	}

	ctx->namesize += snprintf(ctx->namebuffer + ctx->namesize,
				  sizeof(ctx->namebuffer) - ctx->namesize,
				  "/%s=%*.*s",
				  prefix,
				  (int)vlen, (int)vlen, (const char *)value);
	if (ctx->namesize > sizeof(ctx->namebuffer) - 1)
		ctx->namesize = sizeof(ctx->namebuffer) - 1;

	return 0;
}

/*
 * Take a copy of the issuer name.
 */
int x509_note_issuer(void *context, size_t hdrlen,
		     unsigned char tag,
		     const void *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;

	pr_debug("Issuer: %s\n", ctx->namebuffer);

	ctx->cert->issuer = kmalloc(ctx->namesize + 1, GFP_KERNEL);
	if (!ctx->cert->issuer)
		return -ENOMEM;
	memcpy(ctx->cert->issuer, ctx->namebuffer, ctx->namesize);
	ctx->cert->issuer[ctx->namesize] = 0;
	ctx->namesize = 0;
	return 0;
}

/*
 * Take a copy of the subject name.
 */
int x509_note_subject(void *context, size_t hdrlen,
		      unsigned char tag,
		      const void *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	pr_debug("Subject: %s\n", ctx->namebuffer);

	ctx->cert->subject = kmalloc(ctx->namesize + 1, GFP_KERNEL);
	if (!ctx->cert->subject)
		return -ENOMEM;
	memcpy(ctx->cert->subject, ctx->namebuffer, ctx->namesize);
	ctx->cert->subject[ctx->namesize] = 0;
	ctx->namesize = 0;
	return 0;
}

/*
 * Extract the data for the public key algorithm
 */
int x509_extract_key_data(void *context, size_t hdrlen,
			  unsigned char tag,
			  const void *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;

	if (ctx->last_oid != OID_rsaEncryption)
		return -ENOPKG;

	/* There seems to be an extraneous 0 byte on the front of the data */
	ctx->cert->pkey_algo = PKEY_ALGO_RSA;
	ctx->key = value + 1;
	ctx->key_size = vlen - 1;
	return 0;
}

/*
 * Extract a RSA public key value
 */
int rsa_extract_mpi(void *context, size_t hdrlen,
		    unsigned char tag,
		    const void *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	MPI mpi;

	if (ctx->nr_mpi >= ARRAY_SIZE(ctx->cert->pub->mpi)) {
		pr_err("Too many public keys in certificate\n");
		return -EBADMSG;
	}

	mpi = mpi_read_raw_data(value, vlen);
	if (!mpi)
		return -ENOMEM;

	ctx->cert->pub->mpi[ctx->nr_mpi++] = mpi;
	return 0;
}

/*
 * Process certificate extensions that are used to qualify the certificate.
 */
int x509_process_extension(void *context, size_t hdrlen,
			   unsigned char tag,
			   const void *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	const unsigned char *v = value;
	char *f;
	int i;

	pr_debug("Extension: %u\n", ctx->last_oid);

	if (ctx->last_oid == OID_subjectKeyIdentifier) {
		/* Get hold of the key fingerprint */
		if (vlen < 3)
			return -EBADMSG;
		if (v[0] != ASN1_OTS || v[1] != vlen - 2)
			return -EBADMSG;
		v += 2;
		vlen -= 2;

		f = kmalloc(vlen * 2 + 1, GFP_KERNEL);
		if (!f)
			return -ENOMEM;
		for (i = 0; i < vlen; i++)
			sprintf(f + i * 2, "%02x", v[i]);
		pr_debug("fingerprint %s\n", f);
		ctx->cert->fingerprint = f;

		ctx->cert->pub->key_id_size = i =
			min(vlen, sizeof(ctx->cert->pub->key_id));
		memcpy(ctx->cert->pub->key_id, v + vlen - i, i);
		return 0;
	}

	if (ctx->last_oid == OID_authorityKeyIdentifier) {
		/* Get hold of the CA key fingerprint */
		if (vlen < 5)
			return -EBADMSG;
		if (v[0] != (ASN1_SEQ | (ASN1_CONS << 5)) ||
		    v[1] != vlen - 2 ||
		    v[2] != (ASN1_CONT << 6) ||
		    v[3] != vlen - 4)
			return -EBADMSG;
		v += 4;
		vlen -= 4;

		f = kmalloc(vlen * 2 + 1, GFP_KERNEL);
		if (!f)
			return -ENOMEM;
		for (i = 0; i < vlen; i++)
			sprintf(f + i * 2, "%02x", v[i]);
		pr_debug("authority   %s\n", f);
		ctx->cert->authority = f;
		return 0;
	}

	return 0;
}

/*
 * Record the certificate serial number.
 */
int x509_note_serial(void *context, size_t hdrlen,
		     unsigned char tag,
		     const void *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	char *serial;

	for (; vlen > 0; vlen--, value++)
		if (*(const u8 *)value != 0)
			break;

	serial = kmalloc(vlen * 2 + 1, GFP_KERNEL);
	if (!serial)
		return -ENOMEM;
	ctx->cert->serial = serial;

	/* Note: this limits the field width to a maximum of 64 */
	sprintf(serial, "%*phN", (int)vlen, value);

	pr_devel("Serial: %s\n", serial);
	return 0;
}
