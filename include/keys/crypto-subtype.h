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
 * Data parser.  Called during instantiation and signature verification
 * initiation.
 */
struct crypto_key_parser {
	struct list_head	link;
	struct module		*owner;
	const char		*name;

	/* Attempt to instantiate a key from the data blob passed to add_key()
	 * or keyctl_instantiate().
	 *
	 * Return EBADMSG if not recognised.
	 */
	int (*instantiate)(struct key *key, const void *data, size_t datalen);
};

extern int register_crypto_key_parser(struct crypto_key_parser *);
extern void unregister_crypto_key_parser(struct crypto_key_parser *);

#endif /* _KEYS_CRYPTO_SUBTYPE_H */
