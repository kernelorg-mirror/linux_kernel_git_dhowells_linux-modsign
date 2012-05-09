/* Public keys for module signature verification
 *
 * Copyright (C) 2011 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <keys/crypto-type.h>
#include "module-verify-defs.h"

struct key *modsign_keyring;

extern __initdata const u8 modsign_public_keys[];
extern __initdata const u8 modsign_public_keys_end[];
asm(".section .init.data,\"aw\"\n"
    "modsign_public_keys:\n"
    ".incbin \"modsign.pub\"\n"
    "modsign_public_keys_end:"
    );

/*
 * We need to make sure ccache doesn't cache the .o file as it doesn't notice
 * if modsign.pub changes.
 */
static __initdata const char annoy_ccache[] = __TIME__ "foo";

/*
 * Load the compiled-in keys
 */
static __init int module_verify_init(void)
{
	pr_notice("Initialise module verification\n");

	modsign_keyring = key_alloc(&key_type_keyring, ".module_sign",
				    0, 0, current_cred(),
				    (KEY_POS_ALL & ~KEY_POS_SETATTR) |
				    KEY_USR_VIEW | KEY_USR_READ,
				    KEY_ALLOC_NOT_IN_QUOTA);
	if (IS_ERR(modsign_keyring))
		panic("Can't allocate module signing keyring\n");

	if (key_instantiate_and_link(modsign_keyring, NULL, 0, NULL, NULL) < 0)
		panic("Can't instantiate module signing keyring\n");

	return 0;
}

/*
 * Must be initialised before we try and load the keys into the keyring.
 */
device_initcall(module_verify_init);

/*
 * Load the compiled-in keys
 */
static __init int modsign_pubkey_init(void)
{
	pr_notice("Load module verification keys\n");

	if (preload_pgp_keys(modsign_public_keys,
			     modsign_public_keys_end - modsign_public_keys,
			     modsign_keyring, "modsign.") < 0)
		panic("Can't load module signing keys\n");

	return 0;
}
late_initcall(modsign_pubkey_init);
