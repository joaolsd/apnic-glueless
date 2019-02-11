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

#ifndef __UTILS_H
#define __UTILS_H

#include <ldns/ldns.h>

#ifdef __cplusplus
extern "C" {
#endif

ldns_dnssec_zone *util_load_zone(const ldns_rdf *origin, const char *zonefile);
ldns_key_list *util_load_key(const ldns_rdf *origin, const char *keyfile);
ldns_status util_sign_zone(ldns_dnssec_zone *zone, ldns_key_list *keys);

/* TODO: all of the below require error checks */
void LDNS_rr_list_cat_dnssec_rrs_clone(ldns_rr_list *rr_list, ldns_dnssec_rrs *rrs);
void LDNS_rr_list_cat_rr_list_clone(ldns_rr_list *dst, ldns_rr_list *src);
void LDNS_rr_replace_owner(ldns_rr *rr, ldns_rdf *new_owner);
void LDNS_rr_wildcard_substitute(ldns_rr *rr, ldns_rdf *replace);
void LDNS_rr_list_empty_rr_list(ldns_rr_list *rr_list);

#ifdef __cplusplus
}
#endif

#endif /* __UTILS_H */
