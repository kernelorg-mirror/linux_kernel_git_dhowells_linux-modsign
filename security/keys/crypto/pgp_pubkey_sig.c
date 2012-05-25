/* Handling for PGP public key signature data [RFC 4880]
 *
 * Copyright (C) 2011 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define pr_fmt(fmt) "PGPSIG: "fmt
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/pgp.h>
#include "public_key.h"
#include "pgp_parser.h"

const struct {
	enum pkey_hash_algo algo : 8;
} pgp_pubkey_hash[PGP_HASH__LAST] = {
	[PGP_HASH_MD5].algo		= PKEY_HASH_MD5,
	[PGP_HASH_SHA1].algo		= PKEY_HASH_SHA1,
	[PGP_HASH_RIPE_MD_160].algo	= PKEY_HASH_RIPE_MD_160,
	[PGP_HASH_SHA256].algo		= PKEY_HASH_SHA256,
	[PGP_HASH_SHA384].algo		= PKEY_HASH_SHA384,
	[PGP_HASH_SHA512].algo		= PKEY_HASH_SHA512,
	[PGP_HASH_SHA224].algo		= PKEY_HASH_SHA224,
};

static int pgp_pkey_verify_sig_add_data(struct crypto_key_verify_context *ctx,
					const void *data, size_t datalen);
static int pgp_pkey_verify_sig_end(struct crypto_key_verify_context *ctx,
				   const u8 *sig, size_t siglen);
static void pgp_pkey_verify_sig_cancel(struct crypto_key_verify_context *ctx);

struct pgp_pkey_sig_parse_context {
	struct pgp_parse_context pgp;
	struct pgp_sig_parameters params;
};

static int pgp_pkey_parse_signature(struct pgp_parse_context *context,
				    enum pgp_packet_tag type,
				    u8 headerlen,
				    const u8 *data,
				    size_t datalen)
{
	struct pgp_pkey_sig_parse_context *ctx =
		container_of(context, struct pgp_pkey_sig_parse_context, pgp);

	return pgp_parse_sig_params(&data, &datalen, &ctx->params);
}

/*
 * Begin the process of verifying a DSA signature.
 *
 * This involves allocating the hash into which first the data and then the
 * metadata will be put, and parsing the signature to check that it matches the
 * key.
 */
struct crypto_key_verify_context *pgp_pkey_verify_sig_begin(
	struct key *crypto_key, const u8 *sigdata, size_t siglen)
{
	struct pgp_pkey_sig_parse_context p;
	struct public_key_signature *sig;
	struct crypto_shash *tfm;
	const struct public_key *key = crypto_key->payload.data;
	size_t digest_size, desc_size;
	int ret;

	kenter("{%d},,%zu", key_serial(crypto_key), siglen);

	if (!key) {
		kleave(" = -ENOKEY [no public key]");
		return ERR_PTR(-ENOKEY);
	}

	p.pgp.types_of_interest = (1 << PGP_PKT_SIGNATURE);
	p.pgp.process_packet = pgp_pkey_parse_signature;
	ret = pgp_parse_packets(sigdata, siglen, &p.pgp);
	if (ret < 0)
		return ERR_PTR(ret);

	if (p.params.pubkey_algo >= PGP_PUBKEY__LAST ||
	    !pgp_public_key_algorithms[p.params.pubkey_algo]) {
		pr_debug("Unsupported public key algorithm %u\n",
			 p.params.pubkey_algo);
		return ERR_PTR(-ENOPKG);
	}

	if (pgp_public_key_algorithms[p.params.pubkey_algo] != key->algo) {
		kleave(" = -EKEYREJECTED [wrong pk algo]");
		return ERR_PTR(-EKEYREJECTED);
	}

	if (!(key->capabilities & PKEY_CAN_VERIFY)) {
		kleave(" = -EKEYREJECTED [key can't verify]");
		return ERR_PTR(-EKEYREJECTED);
	}

	if (p.params.hash_algo >= PGP_HASH__LAST ||
	    !pgp_hash_algorithms[p.params.hash_algo]) {
		pr_debug("Unsupported hash algorithm %u\n",
			 p.params.hash_algo);
		return ERR_PTR(-ENOPKG);
	}

	pr_debug("Signature generated with %s hash\n",
		 pgp_hash_algorithms[p.params.hash_algo]);

	if (memcmp(&p.params.issuer, key->key_id, 8) != 0) {
		kleave(" = -ENOKEY [wrong key ID]");
		return ERR_PTR(-ENOKEY);
	}

	if (p.params.signature_type != PGP_SIG_BINARY_DOCUMENT_SIG &&
	    p.params.signature_type != PGP_SIG_STANDALONE_SIG) {
		/* We don't want to canonicalise */
		kleave(" = -EOPNOTSUPP [canon]");
		return ERR_PTR(-EOPNOTSUPP);
	}

	/* Allocate the hashing algorithm we're going to need and find out how
	 * big the hash operational data will be.
	 */
	tfm = crypto_alloc_shash(pgp_hash_algorithms[p.params.hash_algo], 0, 0);
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
	sig->base.add_data	= pgp_pkey_verify_sig_add_data;
	sig->base.end		= pgp_pkey_verify_sig_end;
	sig->base.cancel	= pgp_pkey_verify_sig_cancel;
	sig->pkey_hash_algo	= pgp_pubkey_hash[p.params.hash_algo].algo;
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
}

/*
 * Load data into the hash
 */
static int pgp_pkey_verify_sig_add_data(struct crypto_key_verify_context *ctx,
					const void *data, size_t datalen)
{
	struct public_key_signature *sig =
		container_of(ctx, struct public_key_signature, base);

	return crypto_shash_update(&sig->hash, data, datalen);
}

struct pgp_pkey_sig_digest_context {
	struct pgp_parse_context pgp;
	const struct public_key *key;
	struct public_key_signature *sig;
};

/*
 * Extract required metadata from the signature packet and add what we need to
 * to the hash.
 */
static int pgp_pkey_digest_signature(struct pgp_parse_context *context,
				     enum pgp_packet_tag type,
				     u8 headerlen,
				     const u8 *data,
				     size_t datalen)
{
	struct pgp_pkey_sig_digest_context *ctx =
		container_of(context, struct pgp_pkey_sig_digest_context, pgp);
	enum pgp_signature_version version;
	int i;

	kenter(",%u,%u,,%zu", type, headerlen, datalen);

	version = *data;
	if (version == PGP_SIG_VERSION_3) {
		/* We just include an excerpt of the metadata from a V3
		 * signature.
		 */
		crypto_shash_update(&ctx->sig->hash, data + 1, 5);
		data += sizeof(struct pgp_signature_v3_packet);
		datalen -= sizeof(struct pgp_signature_v3_packet);
	} else if (version == PGP_SIG_VERSION_4) {
		/* We add the whole metadata header and some of the hashed data
		 * for a V4 signature, plus a trailer.
		 */
		size_t hashedsz, unhashedsz;
		u8 trailer[6];

		hashedsz = 4 + 2 + (data[4] << 8) + data[5];
		crypto_shash_update(&ctx->sig->hash, data, hashedsz);

		trailer[0] = version;
		trailer[1] = 0xffU;
		trailer[2] = hashedsz >> 24;
		trailer[3] = hashedsz >> 16;
		trailer[4] = hashedsz >> 8;
		trailer[5] = hashedsz;

		crypto_shash_update(&ctx->sig->hash, trailer, 6);
		data += hashedsz;
		datalen -= hashedsz;

		unhashedsz = 2 + (data[0] << 8) + data[1];
		data += unhashedsz;
		datalen -= unhashedsz;
	}

	if (datalen <= 2) {
		kleave(" = -EBADMSG");
		return -EBADMSG;
	}

	/* There's a quick check on the hash available. */
	ctx->sig->signed_hash_msw[0] = *data++;
	ctx->sig->signed_hash_msw[1] = *data++;
	datalen -= 2;

	/* And then the cryptographic data, which we'll need for the
	 * algorithm.
	 */
	for (i = 0; i < ctx->key->algo->n_sig_mpi; i++) {
		unsigned int remaining = datalen;
		if (remaining == 0) {
			pr_debug("short %zu mpi %d\n", datalen, i);
			return -EBADMSG;
		}
		ctx->sig->mpi[i] = mpi_read_from_buffer(data, &remaining);
		if (!ctx->sig->mpi[i])
			return -ENOMEM;
		data += remaining;
		datalen -= remaining;
	}

	if (datalen != 0) {
		kleave(" = -EBADMSG [trailer %zu]", datalen);
		return -EBADMSG;
	}

	kleave(" = 0");
	return 0;
}

/*
 * The data is now all loaded into the hash; load the metadata, finalise the
 * hash and perform the verification step.
 */
static int pgp_pkey_verify_sig_end(struct crypto_key_verify_context *ctx,
				   const u8 *sigdata, size_t siglen)
{
	struct public_key_signature *sig =
		container_of(ctx, struct public_key_signature, base);
	const struct public_key *key = sig->base.key->payload.data;
	struct pgp_pkey_sig_digest_context p;
	int ret;

	kenter("");

	/* Firstly we add metadata, starting with some of the data from the
	 * signature packet */
	p.pgp.types_of_interest = (1 << PGP_PKT_SIGNATURE);
	p.pgp.process_packet = pgp_pkey_digest_signature;
	p.key = key;
	p.sig = sig;
	ret = pgp_parse_packets(sigdata, siglen, &p.pgp);
	if (ret < 0)
		goto error_free_ctx;

	crypto_shash_final(&sig->hash, sig->digest);

	ret = key->algo->verify(key, sig);

error_free_ctx:
	pgp_pkey_verify_sig_cancel(ctx);
	kleave(" = %d", ret);
	return ret;
}

/*
 * Cancel an in-progress data loading
 */
static void pgp_pkey_verify_sig_cancel(struct crypto_key_verify_context *ctx)
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
