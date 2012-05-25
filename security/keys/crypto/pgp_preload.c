/* Cryptographic key request handling
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

#include <linux/module.h>
#include <linux/key.h>
#include <linux/pgp.h>
#include "crypto_keys.h"

struct preload_pgp_keys_context {
	struct pgp_parse_context pgp;
	key_ref_t keyring;
	char descbuf[20];
	u8 key_n;
	u8 dsize;
};

/*
 * Extract a public key or subkey from the PGP stream.
 */
static int __init found_pgp_key(struct pgp_parse_context *context,
				enum pgp_packet_tag type, u8 headerlen,
				const u8 *data, size_t datalen)
{
	struct preload_pgp_keys_context *ctx =
		container_of(context, struct preload_pgp_keys_context, pgp);
	key_ref_t key;

	if (ctx->key_n >= 255)
		return 0; /* Don't overrun descbuf */

	sprintf(ctx->descbuf + ctx->dsize, "%d", ctx->key_n++);

	key = key_create_or_update(ctx->keyring, "crypto", ctx->descbuf,
				   data - headerlen, datalen + headerlen,
				   KEY_POS_ALL | KEY_USR_VIEW,
				   KEY_ALLOC_NOT_IN_QUOTA);

	if (IS_ERR(key))
		return PTR_ERR(key);

	pr_notice("Loaded %s key: %s\n",
		  key_ref_to_ptr(key)->description,
		  crypto_key_id(key_ref_to_ptr(key)));

	key_ref_put(key);
	return 0;
}

/**
 * preload_pgp_keys - Load keys from a PGP keyring blob
 * @pgpdata: The PGP keyring blob containing the keys.
 * @pgpdatalen: The size of the @pgpdata blob.
 * @keyring: The keyring to add the new keys to.
 * @descprefix: The key description prefix.
 *
 * Preload a pack of keys from a PGP keyring blob.
 *
 * The keys are given description of @descprefix + the number of the key in the
 * list.  Since keys can be matched on their key IDs independently of the key
 * description, the description is mostly irrelevant apart from the fact that
 * keys of the same description displace one another from a keyring.
 *
 * The caller should override the current creds if they want the keys to be
 * owned by someone other than the current process's owner.  Keys will not be
 * accounted towards the owner's quota.
 *
 * This function may only be called whilst the kernel is booting.
 */
int __init preload_pgp_keys(const u8 *pgpdata, size_t pgpdatalen,
			    struct key *keyring, const char *descprefix)
{
	struct preload_pgp_keys_context ctx;

	ctx.pgp.types_of_interest =
		(1 << PGP_PKT_PUBLIC_KEY) | (1 << PGP_PKT_PUBLIC_SUBKEY);
	ctx.pgp.process_packet = found_pgp_key;
	ctx.keyring = make_key_ref(keyring, 1);
	ctx.key_n = 0;
	ctx.dsize = strlen(descprefix);
	BUG_ON(ctx.dsize > sizeof(ctx.descbuf) - 4);
	strcpy(ctx.descbuf, descprefix);

	return pgp_parse_packets(pgpdata, pgpdatalen, &ctx.pgp);
}
