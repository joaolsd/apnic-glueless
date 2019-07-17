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
	char host[NI_MAXHOST], port[NI_MAXSERV];

	if (ldns_dname_compare(qname, origin) == 0) {
    // Determine the client's address family in order to derive whether the
		// query at the sibling was for an A or a AAAA RR and adjust the padding
		// later on
		apex_callback(resp, qname, qtype, dnssec_ok);
	} else if (ldns_dname_is_subdomain(qname, origin)) {
		sub_callback(resp, qname, qtype, dnssec_ok);
	} else {
		ldns_pkt_set_rcode(resp, LDNS_RCODE_REFUSED);
	}

	ldns_pkt_set_ancount(resp, ldns_rr_list_rr_count(answer));
	ldns_pkt_set_nscount(resp, ldns_rr_list_rr_count(authority));
}

static ldns_rr* add_stuffing(ldns_rr *old_sig, ldns_rdf *qname, unsigned int type, int len)
{
	if (len > 8192) {
		return NULL;
	}

	/* The Child response without padding already includes a response and an
	RRSIG. In the case of a DNSKEY response with a padding bogus RRSIG in order
	for the total size to be the same as the size of the response from the
	sibling, the padding value needs to be reduced by 460 (0x1cc) bytes. */
	len -= 460;
	if (len <= 0) {
		return NULL;
	}

	uint8_t *data = (uint8_t*)malloc(len);
	ldns_rr *new_sig = ldns_rr_clone(old_sig);
		
	// Adjust fields
	// Change the algorithm to some imaginary number
	auto rdata_alg = ldns_rr_rdf(new_sig, 1);
	auto data_field = (uint8_t *)rdata_alg->_data;
	data_field[0] = 42;
	// Change the KEYID
	auto rdata_keyid = ldns_rr_rdf(new_sig, 6);
	data_field = (uint8_t *)rdata_keyid->_data;
	data_field[0] = rand() % 255;
	// Create a bunch of random data as the new signature
	for (unsigned int i = 0; i < len; ++i) {
		data[i] = rand() & 0xff;
	}
	// put the new signature in place
	ldns_rdf *rdf = ldns_rdf_new(LDNS_RDF_TYPE_NONE, len, data);
	ldns_rr_set_rdf(new_sig, rdf, 8);
	
	return new_sig;
}

void DynamicZone::apex_callback(ldns_pkt *resp, ldns_rdf *qname, ldns_rr_type qtype, bool dnssec_ok)
{
	auto answer = ldns_pkt_answer(resp);
	auto authority = ldns_pkt_authority(resp);
	auto rrsets = ldns_dnssec_zone_find_rrset(zone, qname, qtype);
	ldns_rr *new_sig;
	ldns_dnssec_rrs *new_rrsig;
	ldns_rdf *rdata_sig;
	ldns_rdf *rdata_keyid;
	uint8_t *data_field;

	if (rrsets) {
		LDNS_rr_list_cat_dnssec_rrs_clone(answer, rrsets->rrs);
		if (dnssec_ok) {
			// add optional padding in the form of an arbitrary, fake, RRSIG
			// Get the parameters from the qname
			auto sub_label = ldns_dname_label(qname, 0);
			
			// Create fake signatures to pad the child response
			// unsigned int prelen, pretype, postlen, posttype;
			// auto p = (char *)ldns_rdf_data(sub_label) + 1;
			// bool dostuff = sscanf(p, "%03x-%03x-%04x-%04x-%*04x-", &prelen, &postlen, &pretype, &posttype) == 4;
			//
			// if (dostuff && (prelen > 0 || postlen > 0)) {
			// 	new_sig = add_stuffing((rrsets->signatures)->rr, qname, LDNS_RR_TYPE_RRSIG, prelen+postlen);
			// 	if (new_sig != NULL) {
			// 		ldns_dnssec_rrs_add_rr(rrsets->signatures, new_sig);
			// 	}
			// }
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
	unsigned int timestamp;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	auto p = (char *)ldns_rdf_data(qname) + 1;
	(void)sscanf(p, "%*03x-%*03x-%*04x-%*04x-%*04x-%*08x-%*02d-%10d-", &timestamp);
	// If experiment string timestamp is older than 90 sec, return REFUSED
	if (tv.tv_sec- timestamp > 90) {
		srq->response = evldns_response(srq->request, LDNS_RCODE_REFUSED);
		log_request(logfile.c_str(), srq, qname, qtype, LDNS_RR_CLASS_IN);
		return;
	}
	
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
