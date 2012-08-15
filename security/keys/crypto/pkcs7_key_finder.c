/* PKCS#7 key finder
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */
#define DEBUG
#define pr_fmt(fmt) "PKCS7: "fmt
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include "public_key.h"
#include "pkcs7_parser.h"

/*
 * Attempt to find a key to use for PKCS7 signature verification, starting off by
 * looking in the supplied keyring.
 *
 * The function may also look for other key sources such as a TPM.  If an
 * alternative key is found it can be added to the keyring for future
 * reference.
 */
static struct key *find_key_for_pkcs7_sig(struct key *keyring,
					  const u8 *sig, size_t siglen)
{
	struct pkcs7_signature *pkcs7;
	//key_ref_t key;
	//char criterion[3 + 8 * 2 + 1];
	//int ret;

	if (!keyring)
		return ERR_PTR(-ENOKEY);

	kenter("%02x%02x%02x%02x %02x%02x%02x%02x,%zu",
	       ((const unsigned char *)sig)[0],
	       ((const unsigned char *)sig)[1],
	       ((const unsigned char *)sig)[2],
	       ((const unsigned char *)sig)[3],
	       ((const unsigned char *)sig)[4],
	       ((const unsigned char *)sig)[5],
	       ((const unsigned char *)sig)[6],
	       ((const unsigned char *)sig)[7],
	       siglen);

	/* Need to find the key ID */
	pkcs7 = pkcs7_parse_signature(sig, siglen);
	if (IS_ERR(pkcs7))
		return ERR_CAST(pkcs7);
	pkcs7_free_signature(pkcs7);

	return ERR_PTR(-ENOANO);

#if 0
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
#endif
}

/*
 * Attempt to parse a signature as a PKCS7 packet format blob and find a
 * matching key.
 */
static struct crypto_sig_verify_context *pkcs7_verify_sig_begin(
	struct key *keyring, const u8 *sig, size_t siglen)
{
	struct crypto_sig_verify_context *ctx;
	struct key *key;

	key = find_key_for_pkcs7_sig(keyring, sig, siglen);
	if (IS_ERR(key))
		return ERR_CAST(key);

	/* We only handle in-kernel public key signatures for the moment */
	ctx = pkcs7_do_verify_sig_begin(key, sig, siglen);
	key_put(key);
	return ctx;
}

static struct crypto_sig_parser pkcs7_sig_parser = {
	.owner		= THIS_MODULE,
	.name		= "pkcs7",
	.verify_sig_begin = pkcs7_verify_sig_begin,
};

/*
 * Module stuff
 */
static int __init pkcs7_sig_init(void)
{
	return register_crypto_sig_parser(&pkcs7_sig_parser);
}

static void __exit pkcs7_sig_exit(void)
{
	unregister_crypto_sig_parser(&pkcs7_sig_parser);
}

module_init(pkcs7_sig_init);
module_exit(pkcs7_sig_exit);
