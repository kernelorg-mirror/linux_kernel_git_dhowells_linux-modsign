/* Cryptographic key subtype
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

#ifndef _KEYS_CRYPTO_SUBTYPE_H
#define _KEYS_CRYPTO_SUBTYPE_H

#include <linux/seq_file.h>
#include <keys/crypto-type.h>

extern struct key_type key_type_crypto;

/*
 * Keys of this type declare a subtype that indicates the handlers and
 * capabilities.
 */
struct crypto_key_subtype {
	struct module		*owner;
	const char		*name;
	unsigned short		name_len;	/* length of name */

	void (*describe)(const struct key *key, struct seq_file *m);

	void (*destroy)(void *payload);
};

/*
 * Key data parser.  Called during key instantiation.
 */
struct crypto_key_parser {
	struct list_head	link;
	struct module		*owner;
	const char		*name;

	/* Attempt to parse a key from the data blob passed to add_key() or
	 * keyctl_instantiate().  Should also generate a proposed description
	 * that the caller can optionally use for the key.
	 *
	 * Return EBADMSG if not recognised.
	 */
	int (*preparse)(struct key_preparsed_payload *prep);
};

extern int register_crypto_key_parser(struct crypto_key_parser *);
extern void unregister_crypto_key_parser(struct crypto_key_parser *);

/*
 * Context base for signature verification methods.  Allocated by the subtype
 * and presumably embedded in something appropriate.
 */
struct crypto_sig_verify_context {
	struct key *key;
	struct crypto_sig_parser *parser;
	int (*add_data)(struct crypto_sig_verify_context *ctx,
			const void *data, size_t datalen);
	int (*end)(struct crypto_sig_verify_context *ctx,
		   const u8 *sig, size_t siglen);
	void (*cancel)(struct crypto_sig_verify_context *ctx);
};

/*
 * Signature data parser.  Called during signature verification initiation.
 */
struct crypto_sig_parser {
	struct list_head	link;
	struct module		*owner;
	const char		*name;

	/* Attempt to recognise a signature blob and find a matching key.
	 *
	 * Return EBADMSG if not recognised.
	 */
	struct crypto_sig_verify_context *(*verify_sig_begin)(
		struct key *keyring, const u8 *sig, size_t siglen);
};

extern int register_crypto_sig_parser(struct crypto_sig_parser *);
extern void unregister_crypto_sig_parser(struct crypto_sig_parser *);

#endif /* _KEYS_CRYPTO_SUBTYPE_H */
