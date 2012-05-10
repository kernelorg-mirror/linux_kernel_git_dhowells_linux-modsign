/* Module verification internal definitions
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#ifdef CONFIG_MODULE_SIG

#include <linux/module.h>

extern struct key *modsign_keyring;

/*
 * Internal state
 */
struct module_verify_data {
	struct crypto_key_verify_context *mod_sig; /* Module signing context */
	union {
		const void	*buffer;	/* module buffer */
		const Elf_Ehdr	*hdr;		/* ELF header */
	};
	const Elf_Shdr		*sections;	/* ELF section table */
	const char		*secstrings;	/* ELF section string table */
	const void		*sig;		/* Signature note content */
	size_t			size;		/* module object size */
	size_t			nsects;		/* number of sections */
	size_t			sig_size;	/* Size of signature */
	size_t			signed_size;	/* count of bytes contributed to digest */
	unsigned		*canonlist;	/* list of canonicalised sections */
	unsigned		*canonmap;	/* section canonicalisation map */
	unsigned		ncanon;		/* number of canonicalised sections */
	unsigned		sig_index;	/* module signature section index */
	uint8_t			xcsum;		/* checksum of bytes contributed to digest */
	uint8_t			csum;		/* checksum of bytes representing a section */
};

/*
 * Whether or not we support various types of ELF relocation record
 */
#if defined(MODULE_HAS_ELF_REL_ONLY)
#define is_elf_rel(sh_type)	((sh_type) == SHT_REL)
#define is_elf_rela(sh_type)	(0)
#elif defined(MODULE_HAS_ELF_RELA_ONLY)
#define is_elf_rel(sh_type)	(0)
#define is_elf_rela(sh_type)	((sh_type) == SHT_RELA)
#else
#define is_elf_rel(sh_type)	((sh_type) == SHT_REL)
#define is_elf_rela(sh_type)	((sh_type) == SHT_RELA)
#endif

/*
 * Debugging.  Define DEBUG to enable.
 */
#define _debug(FMT, ...)			      \
	do {					      \
		if (unlikely(modsign_debug))	      \
			pr_debug(FMT, ##__VA_ARGS__); \
	} while(0)

#ifdef DEBUG
#define count_and_csum(C, __p, __n)			\
do {							\
	int __loop;					\
	for (__loop = 0; __loop < __n; __loop++) {	\
		(C)->csum += __p[__loop];		\
		(C)->xcsum += __p[__loop];		\
	}						\
	(C)->signed_size += __n;			\
} while (0)
#else
#define count_and_csum(C, __p, __n)		\
do {						\
} while (0)
#endif

#endif /* CONFIG_MODULE_SIG */
