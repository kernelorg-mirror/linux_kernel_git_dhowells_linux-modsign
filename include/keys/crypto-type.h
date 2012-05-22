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

/*
 * The payload is at the discretion of the subtype.
 */

#endif /* _KEYS_CRYPTO_TYPE_H */
