/* Module signature verification
 *
 * The code in this file examines a signed kernel module and attempts to
 * determine if the PGP signature attached to the end of the module matches the
 * entire content of the module without the signature attached.
 *
 * Copyright (C) 2004, 2011, 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 * - Method specified by Rusty Russell.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/modsign.h>
#include <linux/moduleparam.h>
#include <linux/fips.h>
#include <keys/crypto-type.h>
#include "module-verify.h"

#ifdef CONFIG_MODULE_SIG_FORCE
#define modsign_signedonly true
#else
static bool modsign_signedonly;
#endif

static const char modsign_magic[] = "This Is A Crypto Signed Module";

/*
 * Verify a module's signature, if it has one
 *
 * Returns 0 if module is validly signed, 1 if there's no signature and a
 * negative error code otherwise.
 */
static int module_verify_signature(const void *data, size_t size)
{
	struct crypto_key_verify_context *mod_sig;
	const char *cp, *sig;
	char *end;
	size_t magic_size, sig_size, mod_size;
	int ret;

	magic_size = sizeof(modsign_magic) - 1;
	if (size <= 5 + magic_size)
		return 1;

	if (memcmp(data + size - magic_size, modsign_magic, magic_size) != 0)
		return 1;
	size -= 5 + magic_size;

	cp = data + size;
	sig_size = simple_strtoul(cp, &end, 10);
	if (sig_size >= size || (*end != ' ' && *end != 'T'))
		return -ELIBBAD;

	mod_size = size - sig_size;
	sig = data + mod_size;

	/* Find the crypto key for the module signature
	 * - !!! if this tries to load the required hash algorithm module,
	 *       we will deadlock!!!
	 */
	mod_sig = verify_sig_begin(modsign_keyring, sig, sig_size);
	if (IS_ERR(mod_sig)) {
		pr_err("Couldn't initiate module signature verification: %ld\n",
		       PTR_ERR(mod_sig));
		return PTR_ERR(mod_sig);
	}

	/* Load the module contents into the digest */
	ret = verify_sig_add_data(mod_sig, data, mod_size);
	if (ret < 0) {
		verify_sig_cancel(mod_sig);
		return ret;
	}

	/* Do the actual signature verification */
	ret = verify_sig_end(mod_sig, sig, sig_size);
	pr_devel("verify-sig : %d\n", ret);
	return ret;
}

/*
 * Verify a module's integrity
 */
int module_verify(const void *data, size_t size, bool *_gpgsig_ok)
{
	int ret;

	pr_devel("-->module_verify(,%zu,)\n", size);

	ret = module_verify_signature(data, size);

	pr_devel("module_verify_signature() = %d\n", ret);

        if (ret < 0 && fips_enabled)
                panic("Module verification failed with error %d in FIPS mode\n",
                      ret);

	switch (ret) {
	case 0:			/* Good signature */
		*_gpgsig_ok = true;
		break;
	case 1:			/* Unsigned module */
		if (modsign_signedonly) {
			pr_err("An attempt to load unsigned module was rejected\n");
			return -EKEYREJECTED;
		}
		ret = 0;
		break;
	case -ELIBBAD:
		pr_err("Module format error encountered\n");
		break;
	case -EBADMSG:
		pr_err("Module signature error encountered\n");
		break;
	case -EKEYREJECTED:	/* Signature mismatch or number format error */
		pr_err("Module signature verification failed\n");
		break;
	case -ENOKEY:		/* Signed, but we don't have the public key */
		pr_err("Module signed with unknown public key\n");
		break;
	default:		/* Other error (probably ENOMEM) */
		break;
	}
	return ret;
}

static int __init sign_setup(char *str)
{
#ifndef CONFIG_MODULE_SIG_FORCE
	modsign_signedonly = true;
#endif
	return 0;
}
__setup("enforcemodulesig", sign_setup);
