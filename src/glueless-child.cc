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

class ChildZone {

	ldns_rdf				*origin;
	unsigned int			origin_count;

protected:
	const std::string		domain;
	const std::string		zonefile;
	const std::string		keyfile;
	const std::string		logfile;

public:
	ChildZone(const std::string& domain, const std::string& zonefile, const std::string& keyfile, const std::string& logfile);
	~ChildZone();

public:
	void main_callback(evldns_server_request *srq, ldns_rdf *qname, ldns_rr_type qtype);
};

class DynamicZone : public SignedZone {
public:
	DynamicZone(const std::string& domain, const std::string& zonefile, const std::string& keyfile);
	~DynamicZone();

public:
	void main_callback(evldns_server_request *srq, ldns_rdf *qname, ldns_rr_type qtype);
	void apex_callback(ldns_pkt *resp, ldns_rdf *qname, ldns_rr_type qtype, bool dnssec_ok);
	void sub_callback(ldns_pkt *resp, ldns_rdf *qname, ldns_rr_type qtype, bool dnssec_ok);
};

ChildZone::ChildZone(const std::string& domain, const std::string& zonefile, const std::string& keyfile, const std::string& logfile)
	: domain(domain), zonefile(zonefile), keyfile(keyfile), logfile(logfile)
{
	origin = ldns_dname_new_frm_str(domain.c_str());
	if (!origin) {
		throw std::runtime_error("couldn't parse domain name");
	}
	origin_count = ldns_dname_label_count(origin);
}

ChildZone::~ChildZone()
{
	ldns_rdf_deep_free(origin);
}

// complete zone needs to be synthesised on the fly

DynamicZone::DynamicZone(
	const std::string& domain,
	const std::string& zonefile,
	const std::string& keyfile)
  : SignedZone(domain, zonefile, keyfile)
{
	// find any wildcard rdata in the apex and fix it up
	auto lhs = ldns_dname_label(origin, 0);
	auto apex = zone->soa;
	auto rrsets = apex->rrsets;
	while (rrsets) {
		auto rrs = rrsets->rrs;
		while (rrs) {
			LDNS_rr_wildcard_substitute(rrs->rr, lhs);
			rrs = rrs->next;
		}
		rrsets = rrsets->next;
	}
	ldns_rdf_deep_free(lhs);

	// the zone's OK to sign now
	sign();
}

DynamicZone::~DynamicZone()
{
}

void DynamicZone::main_callback(evldns_server_request *srq, ldns_rdf *qname, ldns_rr_type qtype)
{
	auto req = srq->request;
	auto resp = srq->response = evldns_response(req, LDNS_RCODE_NOERROR);
	auto answer = ldns_pkt_answer(resp);
	auto authority = ldns_pkt_authority(resp);
	bool dnssec_ok = ldns_pkt_edns_do(req);

	if (ldns_dname_compare(qname, origin) == 0) {
		apex_callback(resp, qname, qtype, dnssec_ok);
	} else if (ldns_dname_is_subdomain(qname, origin)) {
		sub_callback(resp, qname, qtype, dnssec_ok);
	} else {
		ldns_pkt_set_rcode(resp, LDNS_RCODE_REFUSED);
	}

	ldns_pkt_set_ancount(resp, ldns_rr_list_rr_count(answer));
	ldns_pkt_set_nscount(resp, ldns_rr_list_rr_count(authority));
}

void DynamicZone::apex_callback(ldns_pkt *resp, ldns_rdf *qname, ldns_rr_type qtype, bool dnssec_ok)
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
		auto soa = zone->soa;
		rrsets = ldns_dnssec_name_find_rrset(soa, LDNS_RR_TYPE_SOA);
		if (qtype == LDNS_RR_TYPE_NSEC) {
			ldns_rr_list_push_rr(answer, ldns_rr_clone(soa->nsec));
			if (dnssec_ok) {
				LDNS_rr_list_cat_dnssec_rrs_clone(answer, soa->nsec_signatures);
			}
		} else {
			ldns_rr_list_push_rr(authority, ldns_rr_clone(soa->nsec));
			LDNS_rr_list_cat_dnssec_rrs_clone(authority, rrsets->rrs);
			if (dnssec_ok) {
				LDNS_rr_list_cat_dnssec_rrs_clone(authority, soa->nsec_signatures);
				LDNS_rr_list_cat_dnssec_rrs_clone(authority, rrsets->signatures);
			}
		}
	}

	ldns_pkt_set_aa(resp, true);
}

void DynamicZone::sub_callback(ldns_pkt *resp, ldns_rdf *qname, ldns_rr_type qtype, bool dnssec_ok)
{
	auto answer = ldns_pkt_answer(resp);
	auto authority = ldns_pkt_authority(resp);

	// synthesize NXDOMAIN answer with NSECs
	ldns_pkt_set_rcode(resp, LDNS_RCODE_NXDOMAIN);
}

void ChildZone::main_callback(evldns_server_request *srq, ldns_rdf *qname, ldns_rr_type qtype)
{
	if (ldns_dname_is_subdomain(qname, origin)) {
		// construct and sign dynamic zone with correct origin
		unsigned int qname_count = ldns_dname_label_count(qname);
		auto label_count = qname_count - origin_count;
		auto child = ldns_dname_clone_from(qname, label_count - 1);
		auto child_str = ldns_rdf2str(child);
		ldns_rdf_deep_free(child);

		DynamicZone dynamic(child_str, zonefile, keyfile);
		dynamic.main_callback(srq, qname, qtype);

		free(child_str);
	} else {
		srq->response = evldns_response(srq->request, LDNS_RCODE_REFUSED);
	}

	truncation_check(srq);
	log_request(logfile.c_str(), srq, qname, qtype, LDNS_RR_CLASS_IN);
}

static void dispatch(evldns_server_request *srq, void *userdata, ldns_rdf *qname, ldns_rr_type qtype, ldns_rr_class qclass)
{
	auto zone = static_cast<ChildZone *>(userdata);
	zone->main_callback(srq, qname, qtype);
}

struct InstanceData {
	int			*fds;
	ChildZone	*zone;
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
	char *hostnames[10]={NULL,};
  int num_hosts = 0;
	const char		*port = "53";
	const char		*domain = "test.dotnxdomain.net";
	const char		*zonefile = "data/zone.wild.test.dotnxdomain.net";
	const char		*keyfile = "data/Ktest.dotnxdomain.net.private";
	const char		*logfile = "./queries-child-%F.log";

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
			case 'l': --argc; logfile = *++argv; break;
			case 'f': --argc; n_forks = atoi(*++argv); break;
			default: exit(1);
		}
		--argc;
		++argv;
	}

	ChildZone		zone(domain, zonefile, keyfile, logfile);
	InstanceData	data = { bind_to_all(hostnames, num_hosts, port, 100), &zone };

	farm(n_forks, n_threads, start_instance, &data, 0);

	return 0;
}
