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
#include "process.h"
#include "logging.h"

class ParentZone : public SignedZone {
private:
	ldns_dnssec_rrsets	*child_nsset = 0;
	ldns_key_list		*childkeys = 0;
	ldns_enum_hash		 algo;
	const std::string	 logfile;

private:
	ldns_rdf *get_child(ldns_rdf *qname, unsigned int& label_count);

public:
	ParentZone(const std::string& domain, const std::string& zonefile,
			   const std::string& keyfile, const char *childkeyfile,
			   const std::string &logfile, ldns_enum_hash algo);
	~ParentZone();

private:
	void deny_wildcard(ldns_pkt *resp);

public:
	void main_callback(evldns_server_request *srq, ldns_rdf *qname, ldns_rr_type qtype);
	void apex_callback(ldns_rdf *qname, ldns_rr_type qtype, bool dnssec_ok, ldns_pkt *resp);
	void referral_callback(ldns_rdf *qname, ldns_rr_type qtype, bool dnssec_ok, ldns_pkt *resp);
};

ParentZone::ParentZone(
	const std::string& domain,
	const std::string& zonefile,
	const std::string& keyfile,
	const char *childkeyfile,
	const std::string& logfile,
	ldns_enum_hash algo)
  : SignedZone(domain, zonefile, keyfile), logfile(logfile), algo(algo)
{
	// the zone's OK to sign immediately
	sign();

	// find the wildcard NS set in the zone and remember it
	auto wild = ldns_dname_new_frm_str("*");
	ldns_dname_cat(wild, origin);
	child_nsset = ldns_dnssec_zone_find_rrset(zone, wild, LDNS_RR_TYPE_NS);
	ldns_rdf_deep_free(wild);
	if (!child_nsset) {
		throw std::runtime_error("zone should contain wildcard NS set");
	}

	if (childkeyfile) {
		childkeys = util_load_key(origin, childkeyfile);
		if (!childkeys) {
			throw std::runtime_error("child key file load failed");
		}
	}
}

ParentZone::~ParentZone()
{
	if (childkeys) {
		ldns_key_list_free(childkeys);
	}
}

void ParentZone::main_callback(evldns_server_request *srq, ldns_rdf *qname, ldns_rr_type qtype)
{
	auto req = srq->request;
	auto resp = srq->response = evldns_response(req, LDNS_RCODE_NOERROR);
	auto answer = ldns_pkt_answer(resp);
	auto authority = ldns_pkt_authority(resp);
	bool dnssec_ok = ldns_pkt_edns_do(req);

	if (ldns_dname_compare(qname, origin) == 0) {
		apex_callback(qname, qtype, dnssec_ok, resp);
	} else if (ldns_dname_is_subdomain(qname, origin)) {
		referral_callback(qname, qtype, dnssec_ok, resp);
	} else {
		ldns_pkt_set_rcode(resp, LDNS_RCODE_REFUSED);
	}

	ldns_pkt_set_ancount(resp, ldns_rr_list_rr_count(answer));
	ldns_pkt_set_nscount(resp, ldns_rr_list_rr_count(authority));

	truncation_check(srq);
	log_request(logfile.c_str(), srq, qname, qtype, LDNS_RR_CLASS_IN);
}

void ParentZone::apex_callback(ldns_rdf *qname, ldns_rr_type qtype, bool dnssec_ok, ldns_pkt *resp)
{
	auto answer = ldns_pkt_answer(resp);
	auto authority = ldns_pkt_authority(resp);
	auto rrsets = ldns_dnssec_zone_find_rrset(zone, qname, qtype);
	if (rrsets) {
		LDNS_rr_list_cat_dnssec_rrs_clone(answer, rrsets->rrs);
		if (dnssec_ok) {
			LDNS_rr_list_cat_dnssec_rrs_clone(answer, rrsets->signatures);
		}
	} else {
		// NSEC query requires special handling
		// NB: zone requires an RR at '\000' to produce
		// the desired minimal enclosing NSEC (RFC 4470)
		auto soa = zone->soa;
		rrsets = ldns_dnssec_name_find_rrset(soa, LDNS_RR_TYPE_SOA);
		if (qtype == LDNS_RR_TYPE_NSEC) {
			ldns_rr_list_push_rr(answer, ldns_rr_clone(soa->nsec));
			if (dnssec_ok) {
				LDNS_rr_list_cat_dnssec_rrs_clone(answer, soa->nsec_signatures);
			}
		} else {
			LDNS_rr_list_cat_dnssec_rrs_clone(authority, rrsets->rrs);
			ldns_rr_list_push_rr(authority, ldns_rr_clone(soa->nsec));
			if (dnssec_ok) {
				LDNS_rr_list_cat_dnssec_rrs_clone(authority, rrsets->signatures);
				LDNS_rr_list_cat_dnssec_rrs_clone(authority, soa->nsec_signatures);
			}
		}
	}

	ldns_pkt_set_aa(resp, 1);
}

// proper NSEC denial of existence
void ParentZone::deny_wildcard(ldns_pkt *resp)
{
	auto authority = ldns_pkt_authority(resp);

	// almost minimally covering NSEC
	auto prev = ldns_dname_new_frm_str(")");
	auto next = ldns_dname_new_frm_str("+");
	ldns_dname_cat(prev, origin);
	ldns_dname_cat(next, origin);
	auto nsec = ldns_create_nsec(prev, next, NULL);

	// NSEC list
	auto nsecs = ldns_rr_list_new();
	ldns_rr_list_push_rr(nsecs, nsec);

	// signed and added to response
	auto rrsigs = ldns_sign_public(nsecs, keys);
	ldns_rr_list_push_rr_list(authority, nsecs);
	ldns_rr_list_push_rr_list(authority, rrsigs);

	// include the SOA too
	auto soa = zone->soa;
	auto rrsets = ldns_dnssec_name_find_rrset(soa, LDNS_RR_TYPE_SOA);
	LDNS_rr_list_cat_dnssec_rrs_clone(authority, rrsets->rrs);
	LDNS_rr_list_cat_dnssec_rrs_clone(authority, rrsets->signatures);

	// free memory
	ldns_rr_list_free(rrsigs);
	ldns_rr_list_free(nsecs);
	ldns_rdf_deep_free(next);
	ldns_rdf_deep_free(prev);
}

void ParentZone::referral_callback(ldns_rdf *qname, ldns_rr_type qtype, bool dnssec_ok, ldns_pkt *resp)
{
	// extract first subdomain label
	unsigned int label_count;
	ldns_rdf *child = get_child(qname, label_count);

	// there isn't really a wildcard here
	if (ldns_dname_is_wildcard(child)) {

		ldns_pkt_set_rcode(resp, LDNS_RCODE_NXDOMAIN);
		if (dnssec_ok) {
			deny_wildcard(resp);
		}

		ldns_rdf_deep_free(child);
		return;
	}

	auto answer = ldns_pkt_answer(resp);
	auto authority = ldns_pkt_authority(resp);

	// check for broken chain flag
	unsigned int flags = 0;
	auto p = (char *)ldns_rdf_data(child) + 1;
	(void)sscanf(p, "%*03x-%*03x-%*04x-%*04x-%04x-", &flags);
	bool broken_chain = (flags & 0x0001);

	// synthesize the DS record(s)
	auto ds_list = ldns_rr_list_new();
	auto ds_keys = childkeys ? childkeys : keys;
	for (int i = 0, n = ldns_key_list_key_count(ds_keys); i < n; ++i) {
		auto key_rr = ldns_key2rr(ldns_key_list_key(ds_keys, i));
		LDNS_rr_replace_owner(key_rr, child);
		auto ds = ldns_key_rr2ds(key_rr, algo);
		if (broken_chain) {
			auto tag = (uint16_t *)ldns_rdf_data(ldns_rr_rdf(ds, 0));
			auto hex = ldns_rdf_data(ldns_rr_rdf(ds, 3));
			*tag ^= -1;
			*hex ^= -1;
		}
		ldns_rr_list_push_rr(ds_list, ds);
		ldns_rr_free(key_rr);
	}

	if (label_count == 1 && qtype == LDNS_RR_TYPE_DS) {
		// explict request for a child DS record
		ldns_rr_list_cat(answer, ds_list);
		if (dnssec_ok) {
			ldns_rr_list_cat(answer, ldns_sign_public(ds_list, keys));
		}
		ldns_pkt_set_aa(resp, 1);	// DS answers are authoritative

	} else {
		ldns_dnssec_rrs *ns = child_nsset->rrs;
		while (ns) {
			auto clone = ldns_rr_clone(ns->rr);

			// replace owner
			LDNS_rr_replace_owner(clone, child);

			// replace any wildcard RDATA on above RRs
			auto child_label = ldns_dname_label(child, 0);
			LDNS_rr_wildcard_substitute(clone, child_label);
			ldns_rdf_deep_free(child_label);

			ldns_rr_list_push_rr(authority, clone);
			ns = ns->next;
		}

		// include DS records and RRSIGs thereof on referrals
		if (dnssec_ok) {
			auto ds_rrsigs = ldns_sign_public(ds_list, keys);
			ldns_rr_list_cat(authority, ds_list);
			ldns_rr_list_cat(authority, ds_rrsigs);
			ldns_rr_list_free(ds_rrsigs); // nb: not deep, RRs moved
		}
	}

	ldns_rr_list_free(ds_list);
	ldns_rdf_deep_free(child);
}

ldns_rdf* ParentZone::get_child(ldns_rdf *qname, unsigned int& label_count)
{
	unsigned int qname_count = ldns_dname_label_count(qname);
	if (qname_count <= origin_count) {
		throw std::runtime_error("impossible label count");
	}

	label_count = qname_count - origin_count;
	return ldns_dname_clone_from(qname, label_count - 1);
}

static void dispatch(evldns_server_request *srq, void *userdata, ldns_rdf *qname, ldns_rr_type qtype, ldns_rr_class qclass)
{
	auto zone = static_cast<ParentZone *>(userdata);
	zone->main_callback(srq, qname, qtype);
}

struct InstanceData {
	int			*fds;
	ParentZone	*zone;
};

static void *start_instance(void *userdata)
{
	auto data = reinterpret_cast<InstanceData *>(userdata);

	EVLDNSBase server(data->fds);
	server.add_callback(dispatch, data->zone);
	server.start();

	return NULL;
}

int main(int argc, char *argv[])
{
	int				n_forks = 4;
	int				n_threads = 0;
	// Max # IPaddresses to bind to = 10, simpler
	const char *hostnames[10]={NULL,};
  int num_hosts = 0;
	const char		*port = "53";
	const char		*domain = "test.dotnxdomain.net";
	const char		*zonefile = "data/zone.test.dotnxdomain.net";
	const char		*keyfile = "data/Ktest.dotnxdomain.net.private";
	const char		*logfile = "./queries-parent-%F.log";
	const char		*childkeyfile = nullptr;
	ldns_enum_hash	 algo = LDNS_SHA256;

	--argc; ++argv;
	while (argc > 0 && **argv == '-') {
		char o = *++*argv;
		switch (o) {
			case 'h': 
				--argc;
				hostnames[num_hosts] = *++argv;
				num_hosts++;
				if (num_hosts > 9) {
					printf("Too many addresses\n");
					exit(1);
				}
				break;
			case 'p': --argc; port = *++argv; break;
			case 'd': --argc; domain = *++argv; break;
			case 'z': --argc; zonefile = *++argv; break;
			case 'k': --argc; keyfile = *++argv; break;
			case 'c': --argc; childkeyfile = *++argv; break;
			case 'l': --argc; logfile = *++argv; break;
			case 'f': --argc; n_forks = atoi(*++argv); break;
			case 'a': --argc; algo = (ldns_enum_hash)atoi(*++argv); break;
			default: exit(1);
		}
		--argc;
		++argv;
	}

	ParentZone		 zone(domain, zonefile, keyfile, childkeyfile, logfile, algo);
	InstanceData	 data = { bind_to_all(hostnames, num_hosts, port, 100), &zone };

	farm(n_forks, n_threads, start_instance, &data, 0);

	return 0;
}
