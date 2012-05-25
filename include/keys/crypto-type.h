/* Cryptographic key type interface
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

#ifndef _KEYS_CRYPTO_TYPE_H
#define _KEYS_CRYPTO_TYPE_H

#include <linux/key-type.h>

extern struct key_type key_type_crypto;

struct crypto_key_verify_context;
extern struct crypto_key_verify_context *verify_sig_begin(
	struct key *key, const void *sig, size_t siglen);
extern int verify_sig_add_data(struct crypto_key_verify_context *ctx,
			       const void *data, size_t datalen);
extern int verify_sig_end(struct crypto_key_verify_context *ctx,
			  const void *sig, size_t siglen);
extern void verify_sig_cancel(struct crypto_key_verify_context *ctx);

/*
 * The payload is at the discretion of the subtype.
 */

extern __init int preload_pgp_keys(const u8 *pgpdata, size_t pgpdatalen,
				   struct key *keyring, const char *descprefix);

#endif /* _KEYS_CRYPTO_TYPE_H */
