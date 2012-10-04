/* EFI signature/key/certificate list parser test
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define pr_fmt(fmt) "EFI: "fmt
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/err.h>
#include <linux/efi.h>
#include <linux/sched.h>
#include <linux/key-type.h>

struct key *efi_keyring;

extern __initdata const u8 efi_signature_list[];
extern __initdata const u8 efi_signature_list_end[];
asm(".section .init.data,\"aw\"\n"
    "efi_signature_list:\n"
    ".incbin \"efi_signature_list\"\n"
    "efi_signature_list_end:"
    );

/*
 * We need to make sure ccache doesn't cache the .o file as it doesn't notice
 * if modsign.pub changes.
 */
static __initdata const char annoy_ccache[] = __TIME__ "foo";

/*
 * Create the EFI keyring
 */
static __init int efi_keyring_init(void)
{
	pr_notice("Initialise module verification\n");

	efi_keyring = key_alloc(&key_type_keyring, ".efi_keyring",
				0, 0, current_cred(),
				(KEY_POS_ALL & ~KEY_POS_SETATTR) |
				KEY_USR_VIEW | KEY_USR_READ,
				KEY_ALLOC_NOT_IN_QUOTA);
	if (IS_ERR(efi_keyring))
		panic("Can't allocate EFI keyring\n");

	if (key_instantiate_and_link(efi_keyring, NULL, 0, NULL, NULL) < 0)
		panic("Can't instantiate EFI keyring\n");

	return 0;
}

/*
 * Must be initialised before we try and load the keys into the keyring.
 */
device_initcall(efi_keyring_init);

/*
 * Load the compiled-in keys
 */
static __init int load_efi_keys(void)
{
	pr_notice("Loading EFI signature list\n");

	parse_efi_signature_list(efi_signature_list,
				 efi_signature_list_end - efi_signature_list,
				 efi_keyring);

	pr_notice("Loaded EFI signature list\n");
	return 0;
}
late_initcall(load_efi_keys);
