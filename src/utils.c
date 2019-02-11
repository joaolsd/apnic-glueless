/*
 * Copyright (C) 2015       Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdlib.h>
#include <stdio.h>

#include "utils.h"

ldns_dnssec_zone *util_load_zone(const ldns_rdf *origin, const char *zonefile)
{
	ldns_dnssec_zone	*zone;
	ldns_status			status;
	FILE				*fp;

	fp = fopen(zonefile, "r");
	if (!fp) {
		perror("util_load_zone");
		return NULL;
	}

	status = ldns_dnssec_zone_new_frm_fp(&zone, fp, origin, 60, LDNS_RR_CLASS_IN);
	fclose(fp);

	if (status != LDNS_STATUS_OK) {
		fprintf(stderr, "error loading zone file: %s\n", ldns_get_errorstr_by_id(status));
		return NULL;
	}

	return zone;
}

ldns_key_list *util_load_key(const ldns_rdf *origin, const char *keyfile)
{
	ldns_key_list		*list;
	ldns_key			*key;
	ldns_status			status;
	FILE				*fp;

	fp = fopen(keyfile, "r");
	if (!fp) {
		perror("util_load_key");
		return NULL;
	}

	status = ldns_key_new_frm_fp(&key, fp);
	fclose(fp);

	if (status != LDNS_STATUS_OK) {
		fprintf(stderr, "error loading key file: %s\n", ldns_get_errorstr_by_id(status));
		return NULL;
	}

	list = ldns_key_list_new();
	ldns_key_set_pubkey_owner(key, ldns_rdf_clone(origin));
	ldns_key_set_inception(key, time(NULL) - 3600);
	ldns_key_list_push_key(list, key);

	return list;
}

void util_add_keys(ldns_dnssec_zone *zone, ldns_key_list *keys)
{
	/* add all the keys to the zone */
	for (int i = 0, n = ldns_key_list_key_count(keys); i < n; ++i) {
		ldns_rr *rr = ldns_key2rr(ldns_key_list_key(keys, i));
		ldns_dnssec_zone_add_rr(zone, rr);
	}
}

ldns_status util_sign_zone(ldns_dnssec_zone *zone, ldns_key_list *keys)
{
	ldns_rr_list		*new_rrs;
	ldns_status			status;

	/* sign the zone, then discard the extra list of RRs */
	new_rrs = ldns_rr_list_new();
	status = ldns_dnssec_zone_sign(zone, new_rrs, keys, ldns_dnssec_default_replace_signatures, 0);
	ldns_rr_list_free(new_rrs);

	return status;
}

void LDNS_rr_list_cat_dnssec_rrs_clone(ldns_rr_list *rr_list, ldns_dnssec_rrs *rrs)
{
	 while (rrs) {
		  ldns_rr_list_push_rr(rr_list, ldns_rr_clone(rrs->rr));
		  rrs = rrs->next;
	 }
}

void LDNS_rr_list_cat_rr_list_clone(ldns_rr_list *dst, ldns_rr_list *src)
{
	 for (int i = 0, n = ldns_rr_list_rr_count(src); i < n; ++i) {
		  ldns_rr_list_push_rr(dst, ldns_rr_clone(ldns_rr_list_rr(src, i)));
	 }
}

void LDNS_rr_replace_owner(ldns_rr *rr, ldns_rdf *new_owner)
{
	ldns_rdf_deep_free(ldns_rr_owner(rr));
	ldns_rr_set_owner(rr, ldns_rdf_clone(new_owner));
}

void LDNS_rr_wildcard_substitute(ldns_rr *rr, ldns_rdf *replace)
{
	for (int i = 0, n = ldns_rr_rd_count(rr); i < n; ++i) {
		ldns_rdf *rdf = ldns_rr_rdf(rr, i);
		if (rdf && ldns_dname_is_wildcard(rdf)) {
			ldns_rdf *rhs = ldns_dname_left_chop(rdf);
			ldns_rdf *new_rdf = ldns_dname_cat_clone(replace, rhs);
			ldns_rr_set_rdf(rr, new_rdf, i);
			ldns_rdf_deep_free(rhs);
			ldns_rdf_deep_free(rdf);
		}
	}
}

void LDNS_rr_list_empty_rr_list(ldns_rr_list *rr_list)
{
	size_t rr_count = ldns_rr_list_rr_count(rr_list);
	while (rr_count--) {
		ldns_rr_free(ldns_rr_list_pop_rr(rr_list));
	}
}
