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
 * Verify the minimum amount of ELF structure of a module needed to check the
 * module's signature without bad ELF crashing the kernel.
 */
static noinline int module_verify_elf(struct module_verify_data *mvdata)
{
	const struct elf_note *note;
	const Elf_Ehdr *hdr = mvdata->hdr;
	const Elf_Shdr *section, *secstop;
	const Elf_Sym *symbols, *symbol, *symstop;
	const char *strtab;
	size_t size, secsize, secstrsize, strsize, notesize, notemetasize;
	unsigned line;

	size = mvdata->size;

#define elfcheck(X)							\
do { if (unlikely(!(X))) { line = __LINE__; goto elfcheck_error; } } while(0)

#define seccheck(X)							\
do { if (unlikely(!(X))) { line = __LINE__; goto seccheck_error; } } while(0)

#define symcheck(X)							\
do { if (unlikely(!(X))) { line = __LINE__; goto symcheck_error; } } while(0)

	/* Validate the ELF header */
	elfcheck(size > sizeof(Elf_Ehdr));
	elfcheck(hdr->e_ehsize < size);

	elfcheck(hdr->e_shnum < SHN_LORESERVE);
	elfcheck(hdr->e_shentsize == sizeof(Elf_Shdr));
	elfcheck(hdr->e_shoff < size);
	elfcheck(hdr->e_shoff >= hdr->e_ehsize);
	elfcheck(hdr->e_shoff % sizeof(long) == 0);
	elfcheck(hdr->e_shstrndx < hdr->e_shnum);

	/* Validate the section table */
	secsize = (size_t)hdr->e_shentsize * (size_t)hdr->e_shnum;
	elfcheck(secsize <= size - hdr->e_shoff);

	mvdata->nsects = hdr->e_shnum;
	mvdata->sections = mvdata->buffer + hdr->e_shoff;
	secstop = mvdata->sections + mvdata->nsects;

	/* Section 0 is special, usually indicating an undefined symbol */
	seccheck(mvdata->sections[SHN_UNDEF].sh_type == SHT_NULL);

	/* We also want access to the section name table */
	seccheck(mvdata->sections[hdr->e_shstrndx].sh_type == SHT_STRTAB);
	secstrsize = mvdata->sections[hdr->e_shstrndx].sh_size;
	seccheck(secstrsize > 1);

	for (section = mvdata->sections + 1; section < secstop; section++) {
		seccheck(section->sh_name < secstrsize);
		seccheck(section->sh_link < hdr->e_shnum);

		/* Section file offsets must reside within the file, though
		 * they don't have to actually consume file space (.bss for
		 * example).
		 */
		seccheck(section->sh_offset >= hdr->e_ehsize);
		seccheck((section->sh_offset & (section->sh_addralign - 1)) == 0);
		seccheck(section->sh_offset <= size);
		if (section->sh_type != SHT_NOBITS)
			seccheck(section->sh_size <= size - section->sh_offset);

		/* Some types of section should contain arrays of fixed-length
		 * records of a predetermined size and mustn't contain partial
		 * records.  Also, records we're going to access directly must
		 * have appropriate alignment that we don't get a misalignment
		 * exception.
		 */
		if (section->sh_entsize > 1)
			seccheck(section->sh_size % section->sh_entsize == 0);

		switch (section->sh_type) {
		case SHT_SYMTAB:
			seccheck(section->sh_entsize == sizeof(Elf_Sym));
			seccheck(section->sh_addralign % sizeof(long) == 0);
			break;
		case SHT_REL:
#ifndef MODULE_HAS_ELF_RELA_ONLY
			seccheck(section->sh_entsize == sizeof(Elf_Rel));
			seccheck(section->sh_addralign % sizeof(long) == 0);
			break;
#else
			seccheck(false);
			break;
#endif
		case SHT_RELA:
#ifndef MODULE_HAS_ELF_REL_ONLY
			seccheck(section->sh_entsize == sizeof(Elf_Rela));
			seccheck(section->sh_addralign % sizeof(long) == 0);
			break;
#else
			seccheck(false);
			break;
#endif
		case SHT_NOTE:
			seccheck(section->sh_addralign % 4 == 0);
			break;
		}
	}

	/* Check features specific to the type of each section.
	 *
	 * Note that having a separate loop here allows the compiler to discard
	 * some local variables used in the above loop thus making the code
	 * smaller.
	 */
	for (section = mvdata->sections + 1; section < secstop; section++) {
		switch (section->sh_type) {
		case SHT_STRTAB:
			/* If not empty, string tables must end in a NUL (it
			 * should also begin with a NUL, but it's not a problem
			 * for us if it doesn't).
			 */
			if (section->sh_size > 0) {
				seccheck(section->sh_size >= 2);
				strtab = mvdata->buffer + section->sh_offset;
				seccheck(strtab[section->sh_size - 1] == '\0');
			}
			break;

		case SHT_SYMTAB:
			/* Symbol tables nominate a string table. */
			seccheck(mvdata->sections[section->sh_link].sh_type ==
				 SHT_STRTAB);

			/* Validate the symbols in the table.  The first symbol
			 * (STN_UNDEF) is special.
			 */
			symbol = symbols = mvdata->buffer + section->sh_offset;
			symstop = mvdata->buffer +
				(section->sh_offset + section->sh_size);

			symcheck(ELF_ST_TYPE(symbols[0].st_info) == STT_NOTYPE);
			symcheck(symbol[0].st_shndx == SHN_UNDEF);

			strsize = mvdata->sections[section->sh_link].sh_size;
			if (strsize == 0)
				strsize = 1; /* st_name of 0 is always okay */
			for (symbol++; symbol < symstop; symbol++) {
				symcheck(symbol->st_name < strsize);
				symcheck(symbol->st_shndx < hdr->e_shnum ||
					 symbol->st_shndx >= SHN_LORESERVE);
			}
			break;

#ifndef MODULE_HAS_ELF_RELA_ONLY
		case SHT_REL:
#endif
#ifndef MODULE_HAS_ELF_REL_ONLY
		case SHT_RELA:
#endif
			/* Relocation tables nominate a symbol table and a
			 * target section to which the relocations will be
			 * applied.
			 */
			seccheck(mvdata->sections[section->sh_link].sh_type ==
				 SHT_SYMTAB);
			seccheck(section->sh_info > 0);
			seccheck(section->sh_info < hdr->e_shnum);
			break;
		}
	}

	/* We can now use section name string table section as we checked its
	 * bounds in the loop above.
	 *
	 * Each name is NUL-terminated, and the table as a whole should have a
	 * NUL at either end as there to be at least one named section for the
	 * module information.
	 */
	section = &mvdata->sections[hdr->e_shstrndx];
	mvdata->secstrings = mvdata->buffer + section->sh_offset;

	for (section = mvdata->sections + 1; section < secstop; section++) {
		const char *name = mvdata->secstrings + section->sh_name;

		switch (section->sh_type) {
		case SHT_NOTE:
			if (strcmp(name, modsign_note_section) != 0)
				continue;

			/* We've found a note purporting to contain a signature
			 * so we should check the structure of that.
			 */
			notemetasize = sizeof(struct elf_note) +
				roundup(sizeof(modsign_note_name), 4);

			seccheck(mvdata->sig_index == 0);
			seccheck(section->sh_size > notemetasize);
			note = mvdata->buffer + section->sh_offset;
			seccheck(note->n_type == MODSIGN_NOTE_TYPE);
			seccheck(note->n_namesz == sizeof(modsign_note_name));

			notesize = section->sh_size - notemetasize;
			seccheck(note->n_descsz <= notesize);

			seccheck(memcmp(note + 1, modsign_note_name,
					note->n_namesz) == 0);

			mvdata->sig_size = note->n_descsz;
			mvdata->sig = (void *)note + notemetasize;
			mvdata->sig_index = section - mvdata->sections;
			break;
		}
	}

	return 0;

elfcheck_error:
	_debug("Verify ELF error (check %u)\n", line);
	return -ELIBBAD;
seccheck_error:
	_debug("Verify ELF error [sec %ld] (check %u)\n",
	       (long)(section - mvdata->sections), line);
	return -ELIBBAD;
symcheck_error:
	_debug("Verify ELF error [sym %ld] (check %u)\n",
	       (long)(symbol - symbols), line);
	return -ELIBBAD;
}

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

	/* Minimally check the ELF to make sure building the signature digest
	 * won't crash the kernel.
	 */
	ret = module_verify_elf(&mvdata);
	if (ret < 0)
		goto out;

	/* The ELF checker found the sig for us if it exists */
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
