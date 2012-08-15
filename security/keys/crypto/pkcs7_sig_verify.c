/* PKCS#7 signature verification [RFC 2315]
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define pr_fmt(fmt) "PKCS7: "fmt
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/pgplib.h>
#include <linux/err.h>
#include "public_key.h"
#include "pgp_parser.h"

static int pkcs7_verify_sig_add_data(struct crypto_sig_verify_context *ctx,
					const void *data, size_t datalen);
static int pkcs7_verify_sig_end(struct crypto_sig_verify_context *ctx,
				   const u8 *sig, size_t siglen);
static void pkcs7_verify_sig_cancel(struct crypto_sig_verify_context *ctx);

/*
 * Begin the process of verifying a signature.
 *
 * This involves allocating the hash into which first the data and then the
 * metadata will be put, and parsing the signature to check that it matches the
 * key.
 */
struct crypto_sig_verify_context *pkcs7_do_verify_sig_begin(
	struct key *crypto_key, const u8 *sigdata, size_t siglen)
{
	//struct public_key_signature *sig;
	//struct crypto_shash *tfm;
	const struct public_key *key = crypto_key->payload.data;
	//size_t digest_size, desc_size;
	//int ret;

	kenter("{%d},,%zu", key_serial(crypto_key), siglen);

	if (!key) {
		kleave(" = -ENOKEY [no public key]");
		return ERR_PTR(-ENOKEY);
	}

	return ERR_PTR(-ENOANO);

#if 0
	if (p.params.pubkey_algo >= PKCS7_PUBKEY__LAST ||
	    !pkcs7_public_key_algorithms[XXXX]) {
		pr_debug("Unsupported public key algorithm %u\n",
			 p.params.pubkey_algo);
		return ERR_PTR(-ENOPKG);
	}

	if (pkcs7_public_key_algorithms[XXXX] != key->algo) {
		kleave(" = -EKEYREJECTED [wrong pk algo]");
		return ERR_PTR(-EKEYREJECTED);
	}

	if (!(key->capabilities & PKEY_CAN_VERIFY)) {
		kleave(" = -EKEYREJECTED [key can't verify]");
		return ERR_PTR(-EKEYREJECTED);
	}

	if (p.params.hash_algo >= PKCS7_HASH__LAST ||
	    !pkcs7_hash_algorithms[XXXX]) {
		pr_debug("Unsupported hash algorithm %u\n",
			 p.params.hash_algo);
		return ERR_PTR(-ENOPKG);
	}

	pr_debug("Signature generated with %s hash\n",
		 pkcs7_hash_algorithms[XXXX]);

	if (memcmp(&p.params.issuer, key->key_id, 8) != 0) {
#error
		kleave(" = -ENOKEY [wrong key ID]");
		return ERR_PTR(-ENOKEY);
	}

	/* Allocate the hashing algorithm we're going to need and find out how
	 * big the hash operational data will be.
	 */
#error	tfm = crypto_alloc_shash(pkcs7_hash_algorithms[XXXX], 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm) == -ENOENT ?
			ERR_PTR(-ENOPKG) : ERR_CAST(tfm);

	desc_size = crypto_shash_descsize(tfm);
	digest_size = crypto_shash_digestsize(tfm);

	/* We allocate the hash operational data storage on the end of our
	 * context data.
	 */
	sig = kzalloc(sizeof(*sig) + desc_size + digest_size, GFP_KERNEL);
	if (!sig) {
		crypto_free_shash(tfm);
		return ERR_PTR(-ENOMEM);
	}

	sig->base.key		= crypto_key;
	sig->base.add_data	= pkcs7_verify_sig_add_data;
	sig->base.end		= pkcs7_verify_sig_end;
	sig->base.cancel	= pkcs7_verify_sig_cancel;
#error	sig->pkey_hash_algo	= 0;
	sig->digest		= (u8 *)sig + sizeof(*sig) + desc_size;
	sig->digest_size	= digest_size;
	sig->hash.tfm		= tfm;
	sig->hash.flags		= CRYPTO_TFM_REQ_MAY_SLEEP;

	ret = crypto_shash_init(&sig->hash);
	if (ret < 0) {
		crypto_free_shash(sig->hash.tfm);
		kfree(sig);
		return ERR_PTR(ret);
	}

	key_get(sig->base.key);
	kleave(" = %p", sig);
	return &sig->base;
#endif
}

/*
 * Load data into the hash
 */
static int pkcs7_verify_sig_add_data(struct crypto_sig_verify_context *ctx,
					const void *data, size_t datalen)
{
	struct public_key_signature *sig =
		container_of(ctx, struct public_key_signature, base);

	return crypto_shash_update(&sig->hash, data, datalen);
}

/*
 * The data is now all loaded into the hash; load the metadata, finalise the
 * hash and perform the verification step.
 */
static int pkcs7_verify_sig_end(struct crypto_sig_verify_context *ctx,
				const u8 *sigdata, size_t siglen)
{
	struct public_key_signature *sig =
		container_of(ctx, struct public_key_signature, base);
	const struct public_key *key = sig->base.key->payload.data;
	int ret;

	kenter("");

	crypto_shash_final(&sig->hash, sig->digest);

	ret = key->algo->verify(key, sig);

error_free_ctx:
	pkcs7_verify_sig_cancel(ctx);
	kleave(" = %d", ret);
	return ret;
}

/*
 * Cancel an in-progress data loading
 */
static void pkcs7_verify_sig_cancel(struct crypto_sig_verify_context *ctx)
{
	struct public_key_signature *sig =
		container_of(ctx, struct public_key_signature, base);
	int i;

	kenter("");

	/* !!! Do we need to tell the crypto layer to cancel too? */
	crypto_free_shash(sig->hash.tfm);
	key_put(sig->base.key);
	for (i = 0; i < ARRAY_SIZE(sig->mpi); i++)
		mpi_free(sig->mpi[i]);
	kfree(sig);

	kleave("");
}
