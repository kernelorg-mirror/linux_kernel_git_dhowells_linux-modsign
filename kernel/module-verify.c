/* Module signature verification
 *
 * The code in this file examines a signed kernel module and attempts to
 * determine if the PGP signature inside the module matches a digest of the
 * allocatable sections and the canonicalised relocation tables for those
 * allocatable sections.
 *
 * The module signature is included in an ELF note within the ELF structure of
 * the module blob.  This, combined with the minimal canonicalisation performed
 * here, permits the module to pass through "strip -x", "strip -g" and
 * "eu-strip" without becoming corrupt.  "strip" and "strip -s" will render a
 * module unusable by removing the symbol table.
 *
 * Copyright (C) 2004, 2011, 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 * - Derived from GregKH's RSA module signer
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#undef DEBUG
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/elf.h>
#include <linux/elfnote.h>
#include <linux/modsign.h>
#include <linux/moduleparam.h>
#include <keys/crypto-type.h>
#include "module-verify.h"
#include "module-verify-defs.h"

#ifdef DEBUG
static int modsign_debug;
core_param(modsign_debug, modsign_debug, int, 0644);
#else
#define modsign_debug false
#endif

#ifdef CONFIG_MODULE_SIG_FORCE
#define modsign_signedonly true
#else
static bool modsign_signedonly;
#endif

static const char modsign_note_name[] = ELFNOTE_NAME(MODSIGN_NOTE_NAME);
static const char modsign_note_section[] = ELFNOTE_SECTION(MODSIGN_NOTE_NAME);

/*
 * Verify a module's integrity
 */
int module_verify(const Elf_Ehdr *hdr, size_t size, bool *_gpgsig_ok)
{
	struct module_verify_data mvdata;
	int ret;

	memset(&mvdata, 0, sizeof(mvdata));
	mvdata.buffer = hdr;
	mvdata.size = size;

	if (mvdata.sig_index <= 0) {
		/* Deal with an unsigned module */
		if (modsign_signedonly) {
			pr_err("An attempt to load unsigned module was rejected\n");
			return -EKEYREJECTED;
		} else {
			return 0;
		}
		goto out;
	}

	ret = 0;

out:
	switch (ret) {
	case 0:			/* Good signature */
		*_gpgsig_ok = true;
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
