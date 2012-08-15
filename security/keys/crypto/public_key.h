/* Asymmetric public-key algorithm definitions
 *
 * Copyright (C) 2011 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#ifndef _LINUX_PUBLIC_KEY_H
#define _LINUX_PUBLIC_KEY_H

#include <linux/mpi.h>
#include <crypto/hash.h>
#include <keys/crypto-subtype.h>

struct public_key;
struct public_key_signature;

enum pkey_algo {
	PKEY_ALGO_DSA,
	PKEY_ALGO_RSA,
	PKEY_ALGO__LAST
};

extern const char *const pkey_algo[PKEY_ALGO__LAST];

enum pkey_hash_algo {
	PKEY_HASH_MD4,
	PKEY_HASH_MD5,
	PKEY_HASH_SHA1,
	PKEY_HASH_RIPE_MD_160,
	PKEY_HASH_SHA256,
	PKEY_HASH_SHA384,
	PKEY_HASH_SHA512,
	PKEY_HASH_SHA224,
	PKEY_HASH__LAST
};

extern const char *const pkey_hash_algo[PKEY_HASH__LAST];

enum pkey_id_type {
	PKEY_ID_PGP,		/* OpenPGP generated key ID */
	PKEY_ID_X509,		/* X.509 arbitrary subjectKeyIdentifier */
	PKEY_ID_TYPE__LAST
};

extern const char *const pkey_id_type[PKEY_ID_TYPE__LAST];

/*
 * Public key type definition
 */
struct public_key_algorithm {
	const char	*name;
	u8		n_pub_mpi;	/* Number of MPIs in public key */
	u8		n_sec_mpi;	/* Number of MPIs in secret key */
	u8		n_sig_mpi;	/* Number of MPIs in a signature */
	int (*verify)(const struct public_key *key,
		      const struct public_key_signature *sig);
};

/*
 * Asymmetric public key data
 */
struct public_key {
	const struct public_key_algorithm *algo;
	u8	capabilities;
#define PKEY_CAN_ENCRYPT	0x01
#define PKEY_CAN_DECRYPT	0x02
#define PKEY_CAN_ENCDEC		(PKEY_CAN_ENCRYPT | PKEY_CAN_DECRYPT)
#define PKEY_CAN_SIGN		0x04
#define PKEY_CAN_VERIFY		0x08
#define PKEY_CAN_SIGVER		(PKEY_CAN_SIGN | PKEY_CAN_VERIFY)
	enum pkey_id_type id_type : 8;
	union {
		MPI	mpi[5];
		struct {
			MPI	p;	/* DSA prime */
			MPI	q;	/* DSA group order */
			MPI	g;	/* DSA group generator */
			MPI	y;	/* DSA public-key value = g^x mod p */
			MPI	x;	/* DSA secret exponent (if present) */
		} dsa;
		struct {
			MPI	n;	/* RSA public modulus */
			MPI	e;	/* RSA public encryption exponent */
			MPI	d;	/* RSA secret encryption exponent (if present) */
			MPI	p;	/* RSA secret prime (if present) */
			MPI	q;	/* RSA secret prime (if present) */
		} rsa;
	};

	u8	key_id[8];	/* ID of this key pair */
	u8	key_id_size;	/* Number of bytes in key_id */
};

/*
 * Asymmetric public key algorithm signature data
 */
struct public_key_signature {
	struct crypto_sig_verify_context base;
	u8 *digest;
	enum pkey_hash_algo pkey_hash_algo : 8;
	u8 signed_hash_msw[2];
	u8 digest_size;	/* Number of bytes in digest */
	union {
		MPI mpi[2];
		struct {
			MPI s;			/* m^d mod n */
		} rsa;
		struct {
			MPI r;
			MPI s;
		} dsa;
	};
	struct shash_desc hash;			/* This must go last! */
};

extern struct crypto_key_subtype public_key_crypto_key_subtype;

#endif /* _LINUX_PUBLIC_KEY_H */
