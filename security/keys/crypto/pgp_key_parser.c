/* Parser for PGP format key data [RFC 4880]
 *
 * Copyright (C) 2011 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define pr_fmt(fmt) "PGP: "fmt
#include <keys/crypto-subtype.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mpi.h>
#include <linux/pgp.h>
#include <crypto/hash.h>
#include "public_key.h"
#include "pgp_parser.h"

MODULE_LICENSE("GPL");

const
struct public_key_algorithm *pgp_public_key_algorithms[PGP_PUBKEY__LAST] = {
#if defined(CONFIG_CRYPTO_KEY_PKEY_ALGO_RSA) || \
	defined(CONFIG_CRYPTO_KEY_PKEY_ALGO_RSA_MODULE)
	[PGP_PUBKEY_RSA_ENC_OR_SIG]	= &RSA_public_key_algorithm,
	[PGP_PUBKEY_RSA_ENC_ONLY]	= &RSA_public_key_algorithm,
	[PGP_PUBKEY_RSA_SIG_ONLY]	= &RSA_public_key_algorithm,
#endif
	[PGP_PUBKEY_ELGAMAL]		= NULL,
	[PGP_PUBKEY_DSA]		= NULL,
};

static const u8 pgp_public_key_capabilities[PGP_PUBKEY__LAST] = {
	[PGP_PUBKEY_RSA_ENC_OR_SIG]	= PKEY_CAN_ENCDEC | PKEY_CAN_SIGVER,
	[PGP_PUBKEY_RSA_ENC_ONLY]	= PKEY_CAN_ENCDEC,
	[PGP_PUBKEY_RSA_SIG_ONLY]	= PKEY_CAN_SIGVER,
	[PGP_PUBKEY_ELGAMAL]		= 0,
	[PGP_PUBKEY_DSA]		= 0,
};

static inline void digest_putc(struct shash_desc *digest, uint8_t ch)
{
	crypto_shash_update(digest, &ch, 1);
}

struct pgp_key_data_parse_context {
	struct pgp_parse_context pgp;
	struct crypto_key_subtype *subtype;
	char *fingerprint;
	void *payload;
};

/*
 * Calculate the public key ID (RFC4880 12.2)
 */
static int pgp_calc_pkey_keyid(struct shash_desc *digest,
			       struct pgp_parse_pubkey *pgp,
			       struct public_key *key)
{
	unsigned nb[ARRAY_SIZE(key->mpi)];
	unsigned nn[ARRAY_SIZE(key->mpi)];
	unsigned n;
	u8 *pp[ARRAY_SIZE(key->mpi)];
	u32 a32;
	int npkey = key->algo->n_pub_mpi;
	int i, ret = -ENOMEM;

	kenter("");

	for (i = 0; i < ARRAY_SIZE(pp); i++)
		pp[i] = NULL;

	n = (pgp->version < PGP_KEY_VERSION_4) ? 8 : 6;
	for (i = 0; i < npkey; i++) {
		nb[i] = mpi_get_nbits(key->mpi[i]);
		pp[i] = mpi_get_buffer(key->mpi[i], nn + i, NULL);
		if (!pp[i])
			goto error;
		n += 2 + nn[i];
	}

	digest_putc(digest, 0x99);     /* ctb */
	digest_putc(digest, n >> 8);   /* 16-bit header length */
	digest_putc(digest, n);
	digest_putc(digest, pgp->version);

	a32 = pgp->creation_time;
	digest_putc(digest, a32 >> 24);
	digest_putc(digest, a32 >> 16);
	digest_putc(digest, a32 >>  8);
	digest_putc(digest, a32 >>  0);

	if (pgp->version < PGP_KEY_VERSION_4) {
		u16 a16;

		if (pgp->expires_at)
			a16 = (pgp->expires_at - pgp->creation_time) / 86400UL;
		else
			a16 = 0;
		digest_putc(digest, a16 >> 8);
		digest_putc(digest, a16 >> 0);
	}

	digest_putc(digest, pgp->pubkey_algo);

	for (i = 0; i < npkey; i++) {
		digest_putc(digest, nb[i] >> 8);
		digest_putc(digest, nb[i]);
		crypto_shash_update(digest, pp[i], nn[i]);
	}
	ret = 0;

error:
	for (i = 0; i < npkey; i++)
		kfree(pp[i]);
	kleave(" = %d", ret);
	return ret;
}

/*
 * Calculate the public key ID fingerprint
 */
static int pgp_generate_fingerprint(struct pgp_key_data_parse_context *ctx,
				    struct pgp_parse_pubkey *pgp,
				    struct public_key *key)
{
	struct crypto_shash *tfm;
	struct shash_desc *digest;
	char *fingerprint;
	u8 *raw_fingerprint;
	int digest_size, offset;
	int ret, i;

	ret = -ENOMEM;
	tfm = crypto_alloc_shash(pgp->version < PGP_KEY_VERSION_4 ?
				 "md5" : "sha1", 0, 0);
	if (!tfm)
		goto cleanup;

	digest = kmalloc(sizeof(*digest) + crypto_shash_descsize(tfm),
			 GFP_KERNEL);
	if (!digest)
		goto cleanup_tfm;

	digest->tfm = tfm;
	digest->flags = CRYPTO_TFM_REQ_MAY_SLEEP;
	ret = crypto_shash_init(digest);
	if (ret < 0)
		goto cleanup_hash;

	ret = pgp_calc_pkey_keyid(digest, pgp, key);
	if (ret < 0)
		goto cleanup_hash;

	digest_size = crypto_shash_digestsize(tfm);

	raw_fingerprint = kmalloc(digest_size, GFP_KERNEL);
	if (!raw_fingerprint)
		goto cleanup_hash;

	ret = crypto_shash_final(digest, raw_fingerprint);
	if (ret < 0)
		goto cleanup_raw_fingerprint;

	fingerprint = kmalloc(digest_size * 2 + 1, GFP_KERNEL);
	if (!fingerprint)
		goto cleanup_raw_fingerprint;

	offset = digest_size - 8;
	pr_debug("offset %u/%u\n", offset, digest_size);

	for (i = 0; i < digest_size; i++)
		sprintf(fingerprint + i * 2, "%02x", raw_fingerprint[i]);
	pr_debug("fingerprint %s\n", fingerprint);

	memcpy(&key->key_id, raw_fingerprint + offset, 8);
	key->key_id_size = 8;

	ctx->fingerprint = fingerprint;
	ret = 0;
cleanup_raw_fingerprint:
	kfree(raw_fingerprint);
cleanup_hash:
	kfree(digest);
cleanup_tfm:
	crypto_free_shash(tfm);
cleanup:
	kleave(" = %d", ret);
	return ret;
}

/*
 * Extract a public key or public subkey from the PGP stream.
 */
static int pgp_process_public_key(struct pgp_parse_context *context,
				  enum pgp_packet_tag type,
				  u8 headerlen,
				  const u8 *data,
				  size_t datalen)
{
	const struct public_key_algorithm *algo;
	struct pgp_key_data_parse_context *ctx =
		container_of(context, struct pgp_key_data_parse_context, pgp);
	struct pgp_parse_pubkey pgp;
	struct public_key *key;
	int i, ret;

	kenter(",%u,%u,,%zu", type, headerlen, datalen);

	if (ctx->subtype) {
		kleave(" = -ENOKEY [already]");
		return -EBADMSG;
	}

	key = kzalloc(sizeof(struct public_key), GFP_KERNEL);
	if (!key)
		return -ENOMEM;

	ret = pgp_parse_public_key(&data, &datalen, &pgp);
	if (ret < 0)
		goto cleanup;

	if (pgp.pubkey_algo >= PGP_PUBKEY__LAST ||
	    !pgp_public_key_algorithms[pgp.pubkey_algo]) {
		pr_debug("Unsupported public key algorithm %u\n",
			 pgp.pubkey_algo);
		ret = -ENOPKG;
		goto cleanup;
	}

	algo = key->algo = pgp_public_key_algorithms[pgp.pubkey_algo];

	/* It's a public key, so that only gives us encrypt and verify
	 * capabilities.
	 */
	key->capabilities = pgp_public_key_capabilities[pgp.pubkey_algo] &
		(PKEY_CAN_ENCRYPT | PKEY_CAN_VERIFY);

	for (i = 0; i < algo->n_pub_mpi; i++) {
		unsigned int remaining = datalen;
		if (remaining == 0) {
			pr_debug("short %zu mpi %d\n", datalen, i);
			goto cleanup_badmsg;
		}
		key->mpi[i] = mpi_read_from_buffer(data, &remaining);
		if (!key->mpi[i])
			goto cleanup_nomem;
		data += remaining;
		datalen -= remaining;
	}

	if (datalen != 0) {
		pr_debug("excess %zu\n", datalen);
		goto cleanup_badmsg;
	}

	ret = pgp_generate_fingerprint(ctx, &pgp, key);
	if (ret < 0)
		goto cleanup;

	/* We're pinning the module by being linked against it */
	__module_get(public_key_crypto_key_subtype.owner);
	ctx->subtype = &public_key_crypto_key_subtype;
	ctx->payload = key;
	kleave(" = 0 [use]");
	return 0;

cleanup_nomem:
	ret = -ENOMEM;
	goto cleanup;
cleanup_badmsg:
	ret = -EBADMSG;
cleanup:
	pr_devel("cleanup");
	if (key) {
		for (i = 0; i < ARRAY_SIZE(key->mpi); i++)
			mpi_free(key->mpi[i]);
		kfree(key);
	}
	kleave(" = %d", ret);
	return ret;
}

/*
 * Attempt to parse the instantiation data blob for a key as a PGP packet
 * message holding a key.
 */
static int pgp_key_instantiate(struct key *key,
			       const void *data, size_t datalen)
{
	struct pgp_key_data_parse_context ctx;
	int ret;

	kenter("");

	ret = key_payload_reserve(key, datalen);
	if (ret < 0)
		return ret;

	ctx.pgp.types_of_interest =
		(1 << PGP_PKT_PUBLIC_KEY) | (1 << PGP_PKT_PUBLIC_SUBKEY);
	ctx.pgp.process_packet = pgp_process_public_key;
	ctx.subtype = NULL;
	ctx.fingerprint = NULL;
	ctx.payload = NULL;

	ret = pgp_parse_packets(data, datalen, &ctx.pgp);
	if (ret < 0) {
		if (ctx.payload)
			ctx.subtype->destroy(ctx.payload);
		if (ctx.subtype)
			module_put(ctx.subtype->owner);
		kfree(ctx.fingerprint);
		key_payload_reserve(key, 0);
		return ret;
	}

	key->type_data.p[0] = ctx.subtype;
	key->type_data.p[1] = ctx.fingerprint;
	key->payload.data = ctx.payload;
	return 0;
}

static struct crypto_key_parser pgp_key_parser = {
	.owner		= THIS_MODULE,
	.name		= "pgp",
	.instantiate	= pgp_key_instantiate,
	.verify_sig_begin = pgp_verify_sig_begin,
};

/*
 * Module stuff
 */
static int __init pgp_key_init(void)
{
	return register_crypto_key_parser(&pgp_key_parser);
}

static void __exit pgp_key_exit(void)
{
	unregister_crypto_key_parser(&pgp_key_parser);
}

module_init(pgp_key_init);
module_exit(pgp_key_exit);
