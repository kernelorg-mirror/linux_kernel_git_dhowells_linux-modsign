/* Instantiate a public key crypto key from an X.509 Certificate
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define pr_fmt(fmt) "X.509: "fmt
#include <keys/crypto-subtype.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/mpi.h>
#include <linux/asn1_decoder.h>
#include <crypto/hash.h>
#include "crypto_keys.h"
#include "x509_parser.h"

static const
struct public_key_algorithm *x509_public_key_algorithms[PKEY_ALGO__LAST] = {
	[PKEY_ALGO_DSA]		= NULL,
#if defined(CONFIG_CRYPTO_KEY_PKEY_ALGO_RSA) || \
	defined(CONFIG_CRYPTO_KEY_PKEY_ALGO_RSA_MODULE)
	[PKEY_ALGO_RSA]		= &RSA_public_key_algorithm,
#endif
};

/*
 * Check the signature on a certificate using the provided public key
 */
static int x509_check_signature(const struct public_key *pub,
				const struct x509_certificate *cert)
{
	struct public_key_signature *sig;
	struct crypto_shash *tfm;
	size_t digest_size, desc_size;
	int ret;
	
	/* Allocate the hashing algorithm we're going to need and find out how
	 * big the hash operational data will be.
	 */
	tfm = crypto_alloc_shash(pkey_hash_algo[cert->sig_hash_algo], 0, 0);
	if (IS_ERR(tfm))
		return (PTR_ERR(tfm) == -ENOENT) ? -ENOPKG : PTR_ERR(tfm);

	desc_size = crypto_shash_descsize(tfm);
	digest_size = crypto_shash_digestsize(tfm);

	/* We allocate the hash operational data storage on the end of our
	 * context data.
	 */
	ret = -ENOMEM;
	sig = kzalloc(sizeof(*sig) + desc_size + digest_size, GFP_KERNEL);
	if (!sig)
		goto error_no_sig;

	sig->base.key		= NULL;
	sig->base.add_data	= NULL;
	sig->base.end		= NULL;
	sig->base.cancel	= NULL;
	sig->pkey_hash_algo	= cert->sig_hash_algo;
	sig->digest		= (u8 *)sig + sizeof(*sig) + desc_size;
	sig->digest_size	= digest_size;
	sig->hash.tfm		= tfm;
	sig->hash.flags		= CRYPTO_TFM_REQ_MAY_SLEEP;

	ret = crypto_shash_init(&sig->hash);
	if (ret < 0)
		goto error;

	ret = -ENOMEM;
	sig->rsa.s = mpi_read_raw_data(cert->sig, cert->sig_size);
	if (!sig->rsa.s)
		goto error;

	ret = crypto_shash_update(&sig->hash, cert->tbs, cert->tbs_size);
	if (ret < 0)
		goto error_mpi;

	ret = crypto_shash_final(&sig->hash, sig->digest);
	if (ret < 0)
		goto error_mpi;

	ret = pub->algo->verify(pub, sig);

	pr_debug("X.509 Cert Verification: %d\n", ret);

error_mpi:
	mpi_free(sig->rsa.s);
error:
	kfree(sig);
error_no_sig:
	crypto_free_shash(tfm);
	return ret;
}

/*
 * Attempt to parse a data blob for a key as an X509 certificate.
 */
static int x509_key_preparse(struct key_preparsed_payload *prep)
{
	struct x509_certificate *cert;
	size_t srlen, sulen;
	char *desc = NULL;
	int ret;

	cert = x509_cert_parse(prep->data, prep->datalen);
	if (IS_ERR(cert))
		return PTR_ERR(cert);

	pr_devel("X.509 Cert Issuer: %s\n", cert->issuer);
	pr_devel("X.509 Cert Subject: %s\n", cert->subject);
	pr_devel("X.509 Key Algo: %s\n", pkey_algo[cert->pkey_algo]);
	pr_devel("X.509 Valid: %lu - %lu\n", cert->valid_from, cert->valid_to);
	pr_devel("X.509 Signature: %s + %s\n",
		 pkey_algo[cert->sig_pkey_algo],
		 pkey_hash_algo[cert->sig_hash_algo]);

	cert->pub->algo = x509_public_key_algorithms[cert->pkey_algo];
	cert->pub->id_type = PKEY_ID_X509;

	/* Check the signature on the key */
	if (strcmp(cert->fingerprint, cert->authority) == 0) {
		ret = x509_check_signature(cert->pub, cert);
		if (ret < 0)
			goto error_free_cert;
	}

	/* Propose a description */
	srlen = strlen(cert->serial);
	sulen = strlen(cert->subject);
	ret = -ENOMEM;
	desc = kmalloc(srlen + sulen + 2, GFP_KERNEL);
	if (!desc)
		goto error_free_cert;
	memcpy(desc, cert->serial, srlen);
	desc[srlen] = ':';
	memcpy(desc + srlen + 1, cert->subject, sulen);
	desc[srlen + sulen + 1] = 0;
	printk("XX%sXX\n", desc);

	/* We're pinning the module by being linked against it */
	__module_get(public_key_crypto_key_subtype.owner);
	prep->type_data[0] = &public_key_crypto_key_subtype;
	prep->type_data[1] = cert->fingerprint;
	prep->payload = cert->pub;
	prep->description = desc;
	prep->quotalen = 100;

	/* We've finished with the certificate */
	cert->pub = NULL;
	cert->fingerprint = NULL;
	desc = NULL;
	ret = 0;

error_free_cert:
	x509_free_certificate(cert);
	return ret;
}

static struct crypto_key_parser x509_key_parser = {
	.owner		= THIS_MODULE,
	.name		= "x509",
	.preparse	= x509_key_preparse,
};

/*
 * Module stuff
 */
static int __init x509_key_init(void)
{
	return register_crypto_key_parser(&x509_key_parser);
}

static void __exit x509_key_exit(void)
{
	unregister_crypto_key_parser(&x509_key_parser);
}

module_init(x509_key_init);
module_exit(x509_key_exit);
