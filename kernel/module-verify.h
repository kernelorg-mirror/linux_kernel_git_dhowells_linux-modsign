/* Module verification definitions
 *
 * Copyright (C) 2004, 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#ifdef CONFIG_MODULE_SIG
extern struct key *modsign_keyring;
extern int module_verify(const void *data, size_t size, const char __user **uargs,
			 bool *_gpgsig_ok);
#else
static inline int module_verify(const void *data, size_t size, const char __user **uargs,
				bool *_gpgsig_ok)
{
	return 0;
}
#endif
