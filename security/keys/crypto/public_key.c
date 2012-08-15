/* Asymmetric public key crypto subtype
 *
 * Copyright (C) 2011 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define pr_fmt(fmt) "PKEY: "fmt
#include <linux/module.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include "public_key.h"

MODULE_LICENSE("GPL");

const char *const pkey_algo[PKEY_ALGO__LAST] = {
	[PKEY_ALGO_DSA]		= "DSA",
	[PKEY_ALGO_RSA]		= "RSA",
};
EXPORT_SYMBOL_GPL(pkey_algo);

const char *const pkey_hash_algo[PKEY_HASH__LAST] = {
	[PKEY_HASH_MD4]		= "md4",
	[PKEY_HASH_MD5]		= "md5",
	[PKEY_HASH_SHA1]	= "sha1",
	[PKEY_HASH_RIPE_MD_160]	= "rmd160",
	[PKEY_HASH_SHA256]	= "sha256",
	[PKEY_HASH_SHA384]	= "sha384",
	[PKEY_HASH_SHA512]	= "sha512",
	[PKEY_HASH_SHA224]	= "sha224",
};
EXPORT_SYMBOL_GPL(pkey_hash_algo);

const char *const pkey_id_type[PKEY_ID_TYPE__LAST] = {
	[PKEY_ID_PGP]		= "PGP",
	[PKEY_ID_X509]		= "X509",
};
EXPORT_SYMBOL_GPL(pkey_id_type);

/*
 * Provide a part of a description of the key for /proc/keys.
 */
static void public_key_describe(const struct key *crypto_key,
				struct seq_file *m)
{
	struct public_key *key = crypto_key->payload.data;

	if (key)
		seq_printf(m, "%s.%s",
			   pkey_id_type[key->id_type], key->algo->name);
}

/*
 * Destroy a public key algorithm key
 */
void public_key_destroy(void *payload)
{
	struct public_key *key = payload;
	int i;

	if (key) {
		for (i = 0; i < ARRAY_SIZE(key->mpi); i++)
			mpi_free(key->mpi[i]);
		kfree(key);
	}
}
EXPORT_SYMBOL_GPL(public_key_destroy);

/*
 * Public key algorithm crypto key subtype
 */
struct crypto_key_subtype public_key_crypto_key_subtype = {
	.owner		= THIS_MODULE,
	.name		= "public_key",
	.describe	= public_key_describe,
	.destroy	= public_key_destroy,
};
EXPORT_SYMBOL_GPL(public_key_crypto_key_subtype);
