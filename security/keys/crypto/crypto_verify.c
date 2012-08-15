/* Signature verification with a crypto key
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
#include <linux/module.h>
#include <linux/err.h>
#include "crypto_keys.h"

static LIST_HEAD(crypto_sig_parsers);

/**
 * verify_sig_begin - Initiate the use of a crypto key to verify a signature
 * @keyring: The public keys to verify against
 * @sig: The signature data
 * @siglen: The signature length
 *
 * Returns a context or an error.
 */
struct crypto_sig_verify_context *verify_sig_begin(
	struct key *keyring, const void *sig, size_t siglen)
{
	struct crypto_sig_verify_context *ret;
	struct crypto_sig_parser *parser;

	pr_devel("==>%s()\n", __func__);

	if (siglen == 0 || !sig)
		return ERR_PTR(-EINVAL);

	down_read(&crypto_key_parsers_sem);

	ret = ERR_PTR(-EBADMSG);
	list_for_each_entry(parser, &crypto_sig_parsers, link) {
		if (parser->verify_sig_begin) {
			if (!try_module_get(parser->owner))
				continue;

			pr_debug("Trying parser '%s'\n", parser->name);

			ret = parser->verify_sig_begin(keyring, sig, siglen);
			if (IS_ERR(ret))
				module_put(parser->owner);
			else
				ret->parser = parser;
			if (ret != ERR_PTR(-EBADMSG)) {
				pr_debug("Parser recognised the format"
					 " (ret %ld)\n",
					 PTR_ERR(ret));
				break;
			}
		}
	}

	up_read(&crypto_key_parsers_sem);
	pr_devel("<==%s() = %p\n", __func__, ret);
	return ret;
}
EXPORT_SYMBOL_GPL(verify_sig_begin);

/**
 * verify_sig_add_data - Incrementally provide data to be verified
 * @ctx: The context from verify_sig_begin()
 * @data: Data
 * @datalen: The amount of @data
 *
 * This may be called multiple times.
 */
int verify_sig_add_data(struct crypto_sig_verify_context *ctx,
			const void *data, size_t datalen)
{
	return ctx->add_data(ctx, data, datalen);
}
EXPORT_SYMBOL_GPL(verify_sig_add_data);

/**
 * verify_sig_end - Finalise signature verification and return result
 * @ctx: The context from verify_sig_begin()
 * @sig: The signature data
 * @siglen: The signature length
 */
int verify_sig_end(struct crypto_sig_verify_context *ctx,
		   const void *sig, size_t siglen)
{
	struct crypto_sig_parser *parser = ctx->parser;
	int ret;

	ret = ctx->end(ctx, sig, siglen);
	module_put(parser->owner);
	return ret;
}
EXPORT_SYMBOL_GPL(verify_sig_end);

/**
 * verify_sig_end - Cancel signature verification
 * @ctx: The context from verify_sig_begin()
 */
void verify_sig_cancel(struct crypto_sig_verify_context *ctx)
{
	struct crypto_sig_parser *parser = ctx->parser;

	ctx->cancel(ctx);
	module_put(parser->owner);
}
EXPORT_SYMBOL_GPL(verify_sig_cancel);

/**
 * register_crypto_sig_parser - Register a crypto sig blob parser
 * @parser: The parser to register
 */
int register_crypto_sig_parser(struct crypto_sig_parser *parser)
{
	struct crypto_sig_parser *cursor;
	int ret;

	down_write(&crypto_key_parsers_sem);

	list_for_each_entry(cursor, &crypto_sig_parsers, link) {
		if (strcmp(cursor->name, parser->name) == 0) {
			pr_err("Crypto signature parser '%s' already registered\n",
			       parser->name);
			ret = -EEXIST;
			goto out;
		}
	}

	list_add_tail(&parser->link, &crypto_sig_parsers);

	pr_notice("Crypto signature parser '%s' registered\n", parser->name);
	ret = 0;

out:
	up_write(&crypto_key_parsers_sem);
	return ret;
}
EXPORT_SYMBOL_GPL(register_crypto_sig_parser);

/**
 * unregister_crypto_sig_parser - Unregister a crypto sig blob parser
 * @parser: The parser to unregister
 */
void unregister_crypto_sig_parser(struct crypto_sig_parser *parser)
{
	down_write(&crypto_key_parsers_sem);
	list_del(&parser->link);
	up_write(&crypto_key_parsers_sem);

	pr_notice("Crypto signature parser '%s' unregistered\n", parser->name);
}
EXPORT_SYMBOL_GPL(unregister_crypto_sig_parser);
