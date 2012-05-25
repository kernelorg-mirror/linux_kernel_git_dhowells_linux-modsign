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
#include <linux/uaccess.h>
#include <linux/ctype.h>
#include <linux/fips.h>
#include <keys/crypto-type.h>
#include "module-verify.h"

#ifdef CONFIG_MODULE_SIG_FORCE
#define modsign_signedonly true
#else
static bool modsign_signedonly;
#endif

static const char kmod_arg_key[] = "modsign=";

/*
 * Extract the module signature from the module argument list if there is one
 *
 * A signature is present if the uargs string begins with "modsign=".  This is
 * followed by a length of up to five decimal digits, then a comma and then the
 * appropriate number of hex digits encoding the signature.
 */
static int module_verify_find_signature(const char __user **_uargs,
					void **_sig, size_t *_sig_size)
{
	const char __user *uargs = *_uargs;
	unsigned char *sig, *dp;
	char prefix[sizeof(kmod_arg_key) + 5 + 1], *end, sp;
	size_t sig_size;
	long tmp;
	int ret;

	if (!uargs)
		return 0;

	tmp = strncpy_from_user(prefix, uargs, sizeof(prefix) - 1);
	if (tmp < 0)
		return -EFAULT;

	if (tmp != sizeof(prefix) - 1)
		return 0;
	if (memcmp(prefix, kmod_arg_key, sizeof(kmod_arg_key) - 1) != 0)
		return 0;
	prefix[sizeof(prefix) - 1] = 0;

	sig_size = simple_strtoul(prefix + sizeof(kmod_arg_key) - 1, &end, 10);
	if (*end != ',' || sig_size == 0)
		return -EINVAL;
	*_sig_size = sig_size;

	uargs += (end - prefix) + 1;

	dp = sig = kmalloc(sig_size, GFP_KERNEL);
	if (!sig)
		return -ENOMEM;

	do {
		unsigned char msn, lsn, bin;

		ret = -EFAULT;
		if (get_user(msn, &uargs[0]) ||
		    get_user(lsn, &uargs[1]))
			goto error;
		uargs += 2;

		ret = -EINVAL;
		if (!isxdigit(msn) || !isxdigit(lsn))
			goto error;
		bin = isdigit(msn) ? msn - '0' : (msn & ~0x20) - 'A' + 0xa;
		bin <<= 4;
		bin += isdigit(lsn) ? lsn - '0' : (lsn & ~0x20) - 'A' + 0xa;
		*dp++ = bin;
	} while (--sig_size > 0);

	pr_debug("%02x%02x%02x%02x...%02x%02x%02x%02x\n",
		 sig[0], sig[1], sig[2], sig[3],
		 dp[-4], dp[-3], dp[-2], dp[-1]);

	ret = -EFAULT;
	if (get_user(sp, uargs))
		goto error;
	ret = -EINVAL;
	if (sp != ' ' && sp != '\0')
		goto error;
	if (sp == ' ')
		uargs++;

	*_sig = sig;
	*_uargs = uargs;
	return 1;
error:
	kfree(sig);
	return ret;
}

/*
 * Verify a module's signature, if it has one
 *
 * Returns 0 if module is validly signed, 1 if there's no signature and a
 * negative error code otherwise.
 */
static int module_verify_signature(const void *data, size_t size,
				   const void *sig, size_t sig_size)
{
	struct crypto_key_verify_context *mod_sig;
	int ret;

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
	ret = verify_sig_add_data(mod_sig, data, size);
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
int module_verify(const void *data, size_t size, const char __user **_uargs,
		  bool *_gpgsig_ok)
{
	size_t sig_size;
	void *sig;
	int ret;

	pr_devel("-->module_verify(,%zu,)\n", size);

	ret = module_verify_find_signature(_uargs, &sig, &sig_size);
	if (ret < 0)
		return ret;

	if (ret == 1) {
		ret = module_verify_signature(data, size, sig, sig_size);
		kfree(sig);
	}

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
