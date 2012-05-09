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

#define crypto_digest_update_data(C, PTR, N)			\
do {								\
	uint8_t *__p = (uint8_t *)(PTR);			\
	size_t __n = (N);					\
	count_and_csum((C), __p, __n);				\
	verify_sig_add_data((C)->mod_sig, __p, __n);		\
} while (0)

#define crypto_digest_update_val(C, VAL)			\
do {								\
	uint8_t *__p = (uint8_t *)&(VAL);			\
	size_t __n = sizeof(VAL);				\
	count_and_csum((C), __p, __n);				\
	verify_sig_add_data((C)->mod_sig, __p, __n);		\
} while (0)

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
 * Canonicalise the section table index numbers.
 *
 * We build a list of the sections we want to add to the digest and sort it by
 * name.  We're only interested in adding two types of section:
 *
 *  (1) Allocatable sections.  These should have no references to other
 *      sections.
 *
 *  (2) Relocation tables for allocatable sections.  The section table entry
 *      has a reference to the target section to which the relocations will be
 *      applied.  The relocation entries have references to symbols in
 *      non-allocatable sections.  Symbols can be replaced by their contents,
 *      but do include a further reference to a section - which must be
 *      canonicalised.
 *
 * We also build a map of raw section index to canonical section index.
 */
static int module_verify_canonicalise(struct module_verify_data *mvdata)
{
	const Elf_Shdr *sechdrs = mvdata->sections;
	unsigned *canonlist, canon, loop, tmp;
	bool changed;

	canonlist = kmalloc(sizeof(unsigned) * mvdata->nsects * 2, GFP_KERNEL);
	if (!canonlist)
		return -ENOMEM;

	mvdata->canonlist = canonlist;
	mvdata->canonmap = canonlist + mvdata->nsects;
	canon = 0;

	for (loop = 1; loop < mvdata->nsects; loop++) {
		const Elf_Shdr *section = mvdata->sections + loop;

		if (loop == mvdata->sig_index)
			continue;

		/* We only want allocatable sections and relocation tables */
		if (section->sh_flags & SHF_ALLOC)
			canonlist[canon++] = loop;
		else if ((is_elf_rel(section->sh_type) ||
			  is_elf_rela(section->sh_type)) &&
			 mvdata->sections[section->sh_info].sh_flags & SHF_ALLOC)
			canonlist[canon++] = loop;
	}

	/* Sort the canonicalisation list */
	do {
		changed = false;

		for (loop = 0; loop < canon - 1; loop++) {
			const char *x, *y;

			x = mvdata->secstrings + sechdrs[canonlist[loop + 0]].sh_name;
			y = mvdata->secstrings + sechdrs[canonlist[loop + 1]].sh_name;

			if (strcmp(x, y) > 0) {
				tmp = canonlist[loop + 0];
				canonlist[loop + 0] = canonlist[loop + 1];
				canonlist[loop + 1] = tmp;
				changed = true;
			}
		}
	} while (changed);

	/* What we really want is a raw-to-canon lookup table */
	memset(mvdata->canonmap, 0xff, mvdata->nsects * sizeof(unsigned));
	for (loop = 0; loop < canon; loop++)
		mvdata->canonmap[mvdata->canonlist[loop]] = loop + 1;
	mvdata->ncanon = canon;
	return 0;
}

/*
 * Extract an ELF REL table
 *
 * We need to canonicalise the entries in case section/symbol addition/removal
 * has rearranged the symbol table and the section table.
 */
static int extract_elf_rel(struct module_verify_data *mvdata,
			   unsigned secix,
			   const Elf_Rel *reltab, size_t nrels,
			   const char *sh_name)
{
	struct {
#if defined(MODULES_ARE_ELF32)
		uint32_t	r_offset;
		uint32_t	st_value;
		uint32_t	st_size;
		uint16_t	st_shndx;
		uint8_t		r_type;
		uint8_t		st_info;
		uint8_t		st_other;
#elif defined(MODULES_ARE_ELF64)
		uint64_t	r_offset;
		uint64_t	st_value;
		uint64_t	st_size;
		uint32_t	r_type;
		uint16_t	st_shndx;
		uint8_t		st_info;
		uint8_t		st_other;
#else
#error unsupported module type
#endif
	} __attribute__((packed)) relocation;

	const Elf_Rel *reloc;
	const Elf_Sym *symbols, *symbol;
	const char *strings;
	unsigned long r_sym;
	size_t nsyms, loop;

	nsyms = mvdata->sections[secix].sh_size / sizeof(Elf_Sym);
	symbols = mvdata->buffer + mvdata->sections[secix].sh_offset;
	strings = mvdata->buffer +
		mvdata->sections[mvdata->sections[secix].sh_link].sh_offset;

	/* Contribute the relevant bits from a join of { REL, SYMBOL, SECTION } */
	for (loop = 0; loop < nrels; loop++) {
		unsigned st_shndx;

		reloc = &reltab[loop];

		/* Decode the relocation */
		relocation.r_offset = reloc->r_offset;
		relocation.r_type = ELF_R_TYPE(reloc->r_info);

		/* Decode the symbol referenced by the relocation */
		r_sym = ELF_R_SYM(reloc->r_info);
		if (r_sym >= nsyms)
			return -ELIBBAD;
		symbol = &symbols[r_sym];
		relocation.st_info = symbol->st_info;
		relocation.st_other = symbol->st_other;
		relocation.st_value = symbol->st_value;
		relocation.st_size = symbol->st_size;
		relocation.st_shndx = symbol->st_shndx;
		st_shndx = symbol->st_shndx;

		/* Canonicalise the section used by the symbol */
		if (st_shndx > SHN_UNDEF && st_shndx < mvdata->nsects) {
			if (!(mvdata->sections[st_shndx].sh_flags & SHF_ALLOC))
				return -ELIBBAD;
			relocation.st_shndx = mvdata->canonmap[st_shndx];
		}

		crypto_digest_update_val(mvdata, relocation);

		/* Undefined symbols must be named if referenced */
		if (st_shndx == SHN_UNDEF) {
			const char *name = strings + symbol->st_name;
			crypto_digest_update_data(mvdata,
						  name, strlen(name) + 1);
		}
	}

	_debug("%08zx %02x digested the %s section, nrels %zu\n",
	       mvdata->signed_size, mvdata->csum, sh_name, nrels);

	return 0;
}

/*
 * Extract an ELF RELA table
 *
 * We need to canonicalise the entries in case section/symbol addition/removal
 * has rearranged the symbol table and the section table.
 */
static int extract_elf_rela(struct module_verify_data *mvdata,
			    unsigned secix,
			    const Elf_Rela *relatab, size_t nrels,
			    const char *sh_name)
{
	struct {
#if defined(MODULES_ARE_ELF32)
		uint32_t	r_offset;
		uint32_t	r_addend;
		uint32_t	st_value;
		uint32_t	st_size;
		uint16_t	st_shndx;
		uint8_t		r_type;
		uint8_t		st_info;
		uint8_t		st_other;
#elif defined(MODULES_ARE_ELF64)
		uint64_t	r_offset;
		uint64_t	r_addend;
		uint64_t	st_value;
		uint64_t	st_size;
		uint32_t	r_type;
		uint16_t	st_shndx;
		uint8_t		st_info;
		uint8_t		st_other;
#else
#error unsupported module type
#endif
	} __attribute__((packed)) relocation;

	const Elf_Shdr *relsec, *symsec, *strsec;
	const Elf_Rela *reloc;
	const Elf_Sym *symbols, *symbol;
	unsigned long r_sym;
	const char *strings;
	size_t nsyms, loop;

	relsec = &mvdata->sections[secix];
	symsec = &mvdata->sections[relsec->sh_link];
	strsec = &mvdata->sections[symsec->sh_link];
	nsyms = symsec->sh_size / sizeof(Elf_Sym);
	symbols = mvdata->buffer + symsec->sh_offset;
	strings = mvdata->buffer + strsec->sh_offset;

	/* Contribute the relevant bits from a join of { RELA, SYMBOL, SECTION } */
	for (loop = 0; loop < nrels; loop++) {
		unsigned st_shndx;

		reloc = &relatab[loop];

		/* Decode the relocation */
		relocation.r_offset = reloc->r_offset;
		relocation.r_addend = reloc->r_addend;
		relocation.r_type = ELF_R_TYPE(reloc->r_info);

		/* Decode the symbol referenced by the relocation */
		r_sym = ELF_R_SYM(reloc->r_info);
		if (r_sym >= nsyms)
			return -ELIBBAD;
		symbol = &symbols[r_sym];
		relocation.st_info = symbol->st_info;
		relocation.st_other = symbol->st_other;
		relocation.st_value = symbol->st_value;
		relocation.st_size = symbol->st_size;
		relocation.st_shndx = 0;
		st_shndx = symbol->st_shndx;

		/* Canonicalise the section used by the symbol */
		if (st_shndx > SHN_UNDEF && st_shndx < mvdata->nsects) {
			if (!(mvdata->sections[st_shndx].sh_flags & SHF_ALLOC))
				return -ELIBBAD;
			relocation.st_shndx = mvdata->canonmap[st_shndx];
		}

		crypto_digest_update_val(mvdata, relocation);

		/* Undefined symbols must be named if referenced */
		if (st_shndx == SHN_UNDEF) {
			const char *name = strings + symbol->st_name;
			crypto_digest_update_data(mvdata,
						  name, strlen(name) + 1);
		}
	}

	_debug("%08zx %02x digested the %s section, nrels %zu\n",
	       mvdata->signed_size, mvdata->csum, sh_name, nrels);

	return 0;
}

/*
 * Verify a module's signature
 */
static noinline int module_verify_signature(struct module_verify_data *mvdata)
{
	struct crypto_key_verify_context *mod_sig;
	const Elf_Shdr *sechdrs = mvdata->sections;
	const char *secstrings = mvdata->secstrings;
	const u8 *sig = mvdata->sig;
	size_t sig_size = mvdata->sig_size;
	int loop, ret;

	_debug("sig in section %u (size %zu)\n",
	       mvdata->sig_index, mvdata->sig_size);
	_debug("%02x%02x%02x%02x%02x%02x%02x%02x\n",
	       sig[0], sig[1], sig[2], sig[3],
	       sig[4], sig[5], sig[6], sig[7]);

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

	mvdata->mod_sig = mod_sig;
#ifdef DEBUG
	mvdata->xcsum = 0;
#endif

	/* Load data from each relevant section into the digest.  Note that
	 * canonlist[] is a filtered list and only contains the sections we
	 * actually want.
	 */
	for (loop = 0; loop < mvdata->ncanon; loop++) {
		int sect = mvdata->canonlist[loop];
		unsigned long sh_type = sechdrs[sect].sh_type;
		unsigned long sh_info = sechdrs[sect].sh_info;
		unsigned long sh_size = sechdrs[sect].sh_size;
		const char *sh_name = secstrings + sechdrs[sect].sh_name;
		const void *data = mvdata->buffer + sechdrs[sect].sh_offset;

#ifdef DEBUG
		mvdata->csum = 0;
#endif

		/* Digest the headers of any section we include. */
		crypto_digest_update_data(mvdata, sh_name, strlen(sh_name));
		crypto_digest_update_val(mvdata, sechdrs[sect].sh_type);
		crypto_digest_update_val(mvdata, sechdrs[sect].sh_flags);
		crypto_digest_update_val(mvdata, sechdrs[sect].sh_size);
		crypto_digest_update_val(mvdata, sechdrs[sect].sh_addralign);

		/* Relocation record sections refer to the section to be
		 * relocated, but this needs to be canonicalised to survive
		 * stripping.
		 */
		if (is_elf_rel(sh_type) || is_elf_rela(sh_type))
			crypto_digest_update_val(mvdata,
						 mvdata->canonmap[sh_info]);

		/* Since relocation records give details of how we have to
		 * alter the allocatable sections, we need to digest these too.
		 *
		 * These, however, refer to metadata (symbols and sections)
		 * that may have been altered by the process of adding the
		 * signature section or the process of being stripped.
		 *
		 * To deal with this, we substitute the referenced metadata for
		 * the references to that metadata.  So, for instance, the
		 * symbol ref from the relocation record is replaced with the
		 * contents of the symbol to which it refers, and the symbol's
		 * section ref is replaced with a canonicalised section number.
		 */
		if (is_elf_rel(sh_type)) {
			ret = extract_elf_rel(mvdata, sect,
					      data,
					      sh_size / sizeof(Elf_Rel),
					      sh_name);
			if (ret < 0)
				goto format_error;
			continue;
		}

		if (is_elf_rela(sh_type)) {
			ret = extract_elf_rela(mvdata, sect,
					       data,
					       sh_size / sizeof(Elf_Rela),
					       sh_name);
			if (ret < 0)
				goto format_error;
			continue;
		}

		/* Include allocatable loadable sections */
		if (sh_type != SHT_NOBITS)
			crypto_digest_update_data(mvdata, data, sh_size);

		_debug("%08zx %02x digested the %s section, size %ld\n",
		       mvdata->signed_size, mvdata->csum, sh_name, sh_size);
	}

	_debug("Contributed %zu bytes to the digest (csum 0x%02x)\n",
	       mvdata->signed_size, mvdata->xcsum);

	/* Do the actual signature verification */
	ret = verify_sig_end(mvdata->mod_sig, sig, sig_size);
	_debug("verify-sig : %d\n", ret);
	return ret;

format_error:
	verify_sig_cancel(mvdata->mod_sig);
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

	/* Produce a canonicalisation map for the sections */
	ret = module_verify_canonicalise(&mvdata);
	if (ret < 0)
		goto out;

	ret = module_verify_signature(&mvdata);
	kfree(mvdata.canonlist);

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
