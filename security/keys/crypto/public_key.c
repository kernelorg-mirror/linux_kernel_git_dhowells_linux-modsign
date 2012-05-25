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
#include <linux/kernel.h>
#include "public_key.h"

MODULE_LICENSE("GPL");

/*
 * Provide a part of a description of the key for /proc/keys.
 */
static void public_key_describe(const struct key *crypto_key,
				struct seq_file *m)
{
	struct public_key *key = crypto_key->payload.data;

	if (key)
		seq_puts(m, key->algo->name);
}

/*
 * Destroy a public key algorithm key
 */
static void public_key_destroy(void *payload)
{
	struct public_key *key = payload;
	int i;

	if (key) {
		for (i = 0; i < ARRAY_SIZE(key->mpi); i++)
			mpi_free(key->mpi[i]);
		kfree(key);
	}
}

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
