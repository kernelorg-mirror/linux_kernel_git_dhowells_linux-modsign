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
#include <linux/pgp.h>
#include "public_key.h"
#include "pgp_parser.h"

struct PGP_sig_parse_context {
	struct pgp_parse_context pgp;
	struct pgp_sig_parameters params;
	bool found_sig;
};

/*
 * Look inside signature sections for a key ID
 */
static int pgp_process_signature(struct pgp_parse_context *context,
				 enum pgp_packet_tag type,
				 u8 headerlen,
				 const u8 *data,
				 size_t datalen)
{
	struct PGP_sig_parse_context *ctx =
		container_of(context, struct PGP_sig_parse_context, pgp);

	ctx->found_sig = true;
	return pgp_parse_sig_params(&data, &datalen, &ctx->params);
}

/*
 * Attempt to find a key to use for PGP signature verification, starting off by
 * looking in the supplied keyring.
 *
 * The function may also look for other key sources such as a TPM.  If an
 * alternative key is found it can be added to the keyring for future
 * reference.
 */
static struct key *find_key_for_pgp_sig(struct key *keyring,
					const u8 *sig, size_t siglen)
{
	struct PGP_sig_parse_context p;
	key_ref_t key;
	char criterion[3 + 8 * 2 + 1];
	int ret;

	if (!keyring)
		return ERR_PTR(-ENOKEY);

	/* Need to find the key ID */
	p.pgp.types_of_interest = (1 << PGP_PKT_SIGNATURE);
	p.pgp.process_packet = pgp_process_signature;
	p.found_sig = false;
	ret = pgp_parse_packets(sig, siglen, &p.pgp);
	if (ret < 0)
		return ERR_PTR(ret);

	if (!p.found_sig)
		return ERR_PTR(-ENOMSG);

	sprintf(criterion, "id:%08x%08x",
		be32_to_cpu(p.params.issuer32[0]),
		be32_to_cpu(p.params.issuer32[1]));

	pr_debug("Look up: %s\n", criterion);

	key = keyring_search(make_key_ref(keyring, 1),
			     &key_type_crypto, criterion);
	if (IS_ERR(key)) {
		switch (PTR_ERR(key)) {
			/* Hide some search errors */
		case -EACCES:
		case -ENOTDIR:
		case -EAGAIN:
			return ERR_PTR(-ENOKEY);
		default:
			return ERR_CAST(key);
		}
	}

	pr_debug("Found key %x\n", key_serial(key_ref_to_ptr(key)));
	return key_ref_to_ptr(key);
}

/*
 * Attempt to parse a signature as a PGP packet format blob and find a
 * matching key.
 */
struct crypto_key_verify_context *pgp_verify_sig_begin(
	struct key *keyring, const u8 *sig, size_t siglen)
{
	struct crypto_key_verify_context *ctx;
	struct key *key;

	key = find_key_for_pgp_sig(keyring, sig, siglen);
	if (IS_ERR(key))
		return ERR_CAST(key);

	/* We only handle in-kernel public key signatures for the moment */
	ctx = pgp_pkey_verify_sig_begin(key, sig, siglen);
	key_put(key);
	return ctx;
}
