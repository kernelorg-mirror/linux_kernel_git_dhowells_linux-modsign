/* Internal crypto type stuff
 *
 * Copyright (C) 2011 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

static inline
struct crypto_key_subtype *crypto_key_subtype(const struct key *key)
{
	return key->type_data.p[0];
}

static inline char *crypto_key_id(const struct key *key)
{
	return key->type_data.p[1];
}


/*
 * crypto_type.c
 */
extern struct list_head crypto_key_parsers;
extern struct rw_semaphore crypto_key_parsers_sem;
