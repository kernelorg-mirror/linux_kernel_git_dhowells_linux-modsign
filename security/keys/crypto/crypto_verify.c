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
#include "crypto_keys.h"

/**
 * verify_sig_begin - Initiate the use of a crypto key to verify a signature
 * @keyring: The public keys to verify against
 * @sig: The signature data
 * @siglen: The signature length
 *
 * Returns a context or an error.
 */
struct crypto_key_verify_context *verify_sig_begin(
	struct key *keyring, const void *sig, size_t siglen)
{
	struct crypto_key_verify_context *ret;
	struct crypto_key_parser *parser;

	pr_devel("==>%s()\n", __func__);

	if (siglen == 0 || !sig)
		return ERR_PTR(-EINVAL);

	down_read(&crypto_key_parsers_sem);

	ret = ERR_PTR(-EBADMSG);
	list_for_each_entry(parser, &crypto_key_parsers, link) {
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
int verify_sig_add_data(struct crypto_key_verify_context *ctx,
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
int verify_sig_end(struct crypto_key_verify_context *ctx,
		   const void *sig, size_t siglen)
{
	struct crypto_key_parser *parser = ctx->parser;
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
void verify_sig_cancel(struct crypto_key_verify_context *ctx)
{
	struct crypto_key_parser *parser = ctx->parser;

	ctx->cancel(ctx);
	module_put(parser->owner);
}
EXPORT_SYMBOL_GPL(verify_sig_cancel);
