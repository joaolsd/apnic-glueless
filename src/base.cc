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

#include <stdexcept>

#include "base.h"
#include "utils.h"

EVLDNSBase::EVLDNSBase(const int *fds)
{
	ev_base = event_base_new();
	ev_server = evldns_add_server(ev_base);
	evldns_add_server_ports(ev_server, fds);
	evldns_add_callback(ev_server, NULL, LDNS_RR_CLASS_ANY, LDNS_RR_TYPE_ANY, query_check, NULL);
}

EVLDNSBase::~EVLDNSBase()
{
}

void EVLDNSBase::add_callback(evldns_callback callback, void *userdata)
{
	evldns_add_callback(ev_server, NULL, LDNS_RR_CLASS_IN, LDNS_RR_TYPE_ANY, callback, userdata);
}

void EVLDNSBase::start()
{
	(void)event_base_dispatch(ev_base);
}

Zone::Zone(const std::string& domain, const std::string& zonefile)
{
	origin = ldns_dname_new_frm_str(domain.c_str());
	if (!origin) {
		throw std::runtime_error("couldn't parse domain");
	}
	origin_count = ldns_dname_label_count(origin);

	zone = util_load_zone(origin, zonefile.c_str());
	if (!zone) {
		throw std::runtime_error("zone file load failed");
	}
}

Zone::~Zone() {
	ldns_dnssec_zone_deep_free(zone);
	ldns_rdf_deep_free(origin);
}

SignedZone::SignedZone(const std::string& domain, const std::string& zonefile, const std::string& keyfile)
	: Zone(domain, zonefile)
{
	keys = util_load_key(origin, keyfile.c_str());
	if (!keys) {
		throw std::runtime_error("key file load failed");
	}
}

void SignedZone::sign()
{
	ldns_status status = util_sign_zone(zone, keys);
	if (status != LDNS_STATUS_OK) {
		throw std::runtime_error("zone signing failed");
	}
}

SignedZone::~SignedZone()
{
	ldns_key_list_free(keys);
}
