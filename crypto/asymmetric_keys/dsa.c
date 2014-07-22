/* DSA asymmetric public-key algorithm
 *
 * Copyright (C) 2011 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define pr_fmt(fmt) "DSA: "fmt
#include <linux/module.h>
#include <linux/kernel.h>
#include "public_key.h"

MODULE_LICENSE("GPL");

#define kenter(FMT, ...) \
	pr_devel("==> %s("FMT")\n", __func__, ##__VA_ARGS__)
#define kleave(FMT, ...) \
	pr_devel("<== %s()"FMT"\n", __func__, ##__VA_ARGS__)

/*
 * Perform the actual mathematical DSA signature verification.
 */
static int DSA_verify(const MPI datahash,
		      const struct public_key_signature *sig,
		      const struct public_key *key)
{
	MPI w = NULL, u1 = NULL, u2 = NULL, v = NULL;
	MPI base[3];
	MPI exp[3];
	int rc;

	kenter("");

	if (!(mpi_cmp_ui(sig->dsa.r, 0) > 0 &&
	      mpi_cmp(sig->dsa.r, key->dsa.q) < 0)) {
		pr_warning("Assertion failed [0 < r < q]\n");
		return -EKEYREJECTED;
	}

	if (!(mpi_cmp_ui(sig->dsa.s, 0) > 0 &&
	      mpi_cmp(sig->dsa.s, key->dsa.q) < 0)) {
		pr_warning("Assertion failed [0 < s < q]\n");
		return -EKEYREJECTED;
	}

	rc = -ENOMEM;
	w  = mpi_alloc(mpi_get_nlimbs(key->dsa.q)); if (!w ) goto cleanup;
	u1 = mpi_alloc(mpi_get_nlimbs(key->dsa.q)); if (!u1) goto cleanup;
	u2 = mpi_alloc(mpi_get_nlimbs(key->dsa.q)); if (!u2) goto cleanup;
	v  = mpi_alloc(mpi_get_nlimbs(key->dsa.p)); if (!v ) goto cleanup;

	/* w = s^(-1) mod q */
	if (mpi_invm(w, sig->dsa.s, key->dsa.q) < 0)
		goto cleanup;

	/* u1 = (datahash * w) mod q */
	if (mpi_mulm(u1, datahash, w, key->dsa.q) < 0)
		goto cleanup;

	/* u2 = r * w mod q  */
	if (mpi_mulm(u2, sig->dsa.r, w, key->dsa.q) < 0)
		goto cleanup;

	/* v =  g^u1 * y^u2 mod p mod q */
	base[0] = key->dsa.g;	exp[0] = u1;
	base[1] = key->dsa.y;	exp[1] = u2;
	base[2] = NULL;		exp[2] = NULL;

	if (mpi_mulpowm(v, base, exp, key->dsa.p) < 0)
		goto cleanup;

	if (mpi_fdiv_r(v, v, key->dsa.q) < 0)
		goto cleanup;

	rc = (mpi_cmp(v, sig->dsa.r) == 0) ? 0 : -EKEYREJECTED;

cleanup:
	mpi_free(w);
	mpi_free(u1);
	mpi_free(u2);
	mpi_free(v);
	kleave(" = %d", rc);
	return rc;
}

/*
 * Perform the verification step.
 */
static int DSA_verify_signature(const struct public_key *key,
				const struct public_key_signature *sig)
{
	MPI datahash = NULL;
	int ret;

	kenter("");

	ret = -ENOMEM;
	datahash = mpi_alloc((sig->digest_size + BYTES_PER_MPI_LIMB - 1) /
			     BYTES_PER_MPI_LIMB);
	if (!datahash)
		goto error;

	ret = mpi_set_buffer(datahash, sig->digest, sig->digest_size, 0);
	if (ret < 0)
		goto error;

	ret = DSA_verify(datahash, sig, key);

error:
	mpi_free(datahash);
	kleave(" = %d", ret);
	return ret;
}

const struct public_key_algorithm DSA_public_key_algorithm = {
	.name		= "DSA",
	.n_pub_mpi	= 4,
	.n_sec_mpi	= 1,
	.n_sig_mpi	= 2,
	.verify_signature = DSA_verify_signature,
};
EXPORT_SYMBOL_GPL(DSA_public_key_algorithm);
