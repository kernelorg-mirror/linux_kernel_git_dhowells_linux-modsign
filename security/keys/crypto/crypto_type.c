/* Cryptographic key type
 *
 * Copyright (C) 2011 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 *
 * See Documentation/security/keys-crypto.txt
 */
#include <keys/crypto-subtype.h>
#include <linux/seq_file.h>
#include <linux/module.h>
#include <linux/slab.h>
#include "crypto_keys.h"

MODULE_LICENSE("GPL");

LIST_HEAD(crypto_key_parsers);
DECLARE_RWSEM(crypto_key_parsers_sem);

/*
 * Match crypto_keys on (part of) their name
 * We have some shorthand methods for matching keys.  We allow:
 *
 *	"<desc>"	- request a key by description
 *	"id:<id>"	- request a key matching the ID
 *	"<subtype>:<id>" - request a key of a subtype
 */
static int crypto_key_match(const struct key *key, const void *description)
{
	const struct crypto_key_subtype *subtype = crypto_key_subtype(key);
	const char *spec = description;
	const char *id, *kid;
	ptrdiff_t speclen;
	size_t idlen, kidlen;

	if (!subtype || !spec || !*spec)
		return 0;

	/* See if the full key description matches as is */
	if (key->description && strcmp(key->description, description) == 0)
		return 1;

	/* All tests from here on break the criterion description into a
	 * specifier, a colon and then an identifier.
	 */
	id = strchr(spec, ':');
	if (!id)
		return 0;

	speclen = id - spec;
	id++;

	/* Anything after here requires a partial match on the ID string */
	kid = crypto_key_id(key);
	if (!kid)
		return 0;

	idlen = strlen(id);
	kidlen = strlen(kid);
	if (idlen > kidlen)
		return 0;

	kid += kidlen - idlen;
	if (strcasecmp(id, kid) != 0)
		return 0;

	if (speclen == 2 &&
	    memcmp(spec, "id", 2) == 0)
		return 1;

	if (speclen == subtype->name_len &&
	    memcmp(spec, subtype->name, speclen) == 0)
		return 1;

	return 0;
}

/*
 * Describe the crypto key
 */
static void crypto_key_describe(const struct key *key, struct seq_file *m)
{
	const struct crypto_key_subtype *subtype = crypto_key_subtype(key);
	const char *kid = crypto_key_id(key);
	size_t n;

	seq_puts(m, key->description);

	if (subtype) {
		seq_puts(m, ": ");
		subtype->describe(key, m);

		if (kid) {
			seq_putc(m, ' ');
			n = strlen(kid);
			if (n <= 8)
				seq_puts(m, kid);
			else
				seq_puts(m, kid + n - 8);
		}

		seq_puts(m, " [");
		/* put something here to indicate the key's capabilities */
		seq_putc(m, ']');
	}
}

/*
 * Instantiate a crypto_key defined key
 */
static int crypto_key_instantiate(struct key *key,
				  const void *data, size_t datalen)
{
	struct crypto_key_parser *parser;
	int ret;

	pr_devel("==>%s()\n", __func__);

	if (datalen == 0)
		return -EINVAL;

	down_read(&crypto_key_parsers_sem);

	ret = -EBADMSG;
	list_for_each_entry(parser, &crypto_key_parsers, link) {
		pr_debug("Trying parser '%s'\n", parser->name);

		ret = parser->instantiate(key, data, datalen);
		if (ret != -EBADMSG) {
			pr_debug("Parser recognised the format (ret %d)\n",
				 ret);
			break;
		}
	}

	up_read(&crypto_key_parsers_sem);
	pr_devel("<==%s() = %d\n", __func__, ret);
	return ret;
}

/*
 * dispose of the data dangling from the corpse of a crypto key
 */
static void crypto_key_destroy(struct key *key)
{
	struct crypto_key_subtype *subtype = crypto_key_subtype(key);
	if (subtype) {
		subtype->destroy(key->payload.data);
		module_put(subtype->owner);
		key->type_data.p[0] = NULL;
	}
	kfree(key->type_data.p[1]);
	key->type_data.p[1] = NULL;
}

struct key_type key_type_crypto = {
	.name		= "crypto",
	.instantiate	= crypto_key_instantiate,
	.match		= crypto_key_match,
	.destroy	= crypto_key_destroy,
	.describe	= crypto_key_describe,
};
EXPORT_SYMBOL_GPL(key_type_crypto);

/**
 * register_crypto_key_parser - Register a crypto key blob parser
 * @parser: The parser to register
 */
int register_crypto_key_parser(struct crypto_key_parser *parser)
{
	struct crypto_key_parser *cursor;
	int ret;

	down_write(&crypto_key_parsers_sem);

	list_for_each_entry(cursor, &crypto_key_parsers, link) {
		if (strcmp(cursor->name, parser->name) == 0) {
			pr_err("Crypto key parser '%s' already registered\n",
			       parser->name);
			ret = -EEXIST;
			goto out;
		}
	}

	list_add_tail(&parser->link, &crypto_key_parsers);

	pr_notice("Crypto key parser '%s' registered\n", parser->name);
	ret = 0;

out:
	up_write(&crypto_key_parsers_sem);
	return ret;
}
EXPORT_SYMBOL_GPL(register_crypto_key_parser);

/**
 * unregister_crypto_key_parser - Unregister a crypto key blob parser
 * @parser: The parser to unregister
 */
void unregister_crypto_key_parser(struct crypto_key_parser *parser)
{
	down_write(&crypto_key_parsers_sem);
	list_del(&parser->link);
	up_write(&crypto_key_parsers_sem);

	pr_notice("Crypto key parser '%s' unregistered\n", parser->name);
}
EXPORT_SYMBOL_GPL(unregister_crypto_key_parser);

/*
 * Module stuff
 */
static int __init crypto_key_init(void)
{
	return register_key_type(&key_type_crypto);
}

static void __exit crypto_key_cleanup(void)
{
	unregister_key_type(&key_type_crypto);
}

module_init(crypto_key_init);
module_exit(crypto_key_cleanup);
