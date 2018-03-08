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
#include <cstdio>

#include "base.h"
#include "utils.h"
#include "process.h"
#include "logging.h"
	
#include <signal.h>
#include <time.h>

extern "C" {
#include "atr_handler.h"
}

class SiblingZone : public Zone {
private:
	ldns_rdf			*wild;
	const std::string	 logfile;

public:
	SiblingZone(const std::string& domain, const std::string& zonefile, const std::string& logfile);
	~SiblingZone();

public:
	void main_callback(evldns_server_request *srq, ldns_rdf *qname, ldns_rr_type qtype);
	void apex_callback(ldns_rdf *qname, ldns_rr_type qtype, ldns_pkt *resp);
	void sub_callback(ldns_rdf *qname, ldns_rr_type qtype, ldns_pkt *resp, evldns_server_request *srq, bool *ignore_edns_size);
};

SiblingZone::SiblingZone(
	const std::string& domain,
	const std::string& zonefile,
	const std::string& logfile)
  : Zone(domain, zonefile), logfile(logfile)
{
	wild = ldns_dname_new_frm_str("*");
	ldns_dname_cat(wild, origin);
}

SiblingZone::~SiblingZone()
{
	ldns_rdf_deep_free(wild);
}

void SiblingZone::main_callback(evldns_server_request *srq, ldns_rdf *qname, ldns_rr_type qtype)
{	
	auto req = srq->request;
	auto resp = srq->response = evldns_response(req, LDNS_RCODE_NOERROR);
	auto answer = ldns_pkt_answer(resp);
	auto authority = ldns_pkt_authority(resp);
	
	bool ignore_edns_size = false;
	
	if (ldns_dname_compare(qname, origin) == 0) {
		apex_callback(qname, qtype, resp);
	} else if (ldns_dname_is_subdomain(qname, origin)) {
		sub_callback(qname, qtype, resp, srq, &ignore_edns_size);
	} else {
		ldns_pkt_set_rcode(resp, LDNS_RCODE_REFUSED);
		return;
	}

	// include the SOA if no answers resulted
	if (ldns_rr_list_rr_count(answer) == 0) {
		auto soa = zone->soa;
		auto rrsets = ldns_dnssec_name_find_rrset(soa, LDNS_RR_TYPE_SOA);
		LDNS_rr_list_cat_dnssec_rrs_clone(authority, rrsets->rrs);
	}

	ldns_pkt_set_ancount(resp, ldns_rr_list_rr_count(answer));
	ldns_pkt_set_nscount(resp, ldns_rr_list_rr_count(authority));
	ldns_pkt_set_aa(resp, 1);

	truncation_check(srq, ignore_edns_size);
	log_request(logfile.c_str(), srq, qname, qtype, LDNS_RR_CLASS_IN);
}

void SiblingZone::apex_callback(ldns_rdf *qname, ldns_rr_type qtype, ldns_pkt *resp)
{
	auto answer = ldns_pkt_answer(resp);
	auto authority = ldns_pkt_authority(resp);
	auto rrsets = ldns_dnssec_zone_find_rrset(zone, qname, qtype);
	if (rrsets) {
		LDNS_rr_list_cat_dnssec_rrs_clone(answer, rrsets->rrs);
	} else {
		auto soa = zone->soa;
		rrsets = ldns_dnssec_name_find_rrset(soa, LDNS_RR_TYPE_SOA);
		LDNS_rr_list_cat_dnssec_rrs_clone(authority, rrsets->rrs);
	}
}

static void add_stuffing(ldns_rr_list *section, ldns_rdf *qname, unsigned int type, unsigned int len)
{
	if (len > 8192) {
		return;
	}

	uint8_t *data = (uint8_t*)malloc(len);
	ldns_rr *rr = ldns_rr_new();
	ldns_rdf *rdf = ldns_rdf_new(LDNS_RDF_TYPE_NONE, len, data);
	for (unsigned int i = 0; i < len; ++i) {
		data[i] = rand() & 0xff;
	}

	ldns_rr_set_owner(rr, ldns_rdf_clone(qname));
	ldns_rr_set_type(rr, (ldns_rr_type) type);
	ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);
	ldns_rr_set_ttl(rr, 600L);
	ldns_rr_push_rdf(rr, rdf);
	ldns_rr_list_push_rr(section, rr);
}

void SiblingZone::sub_callback(ldns_rdf *qname, ldns_rr_type qtype, ldns_pkt *resp, evldns_server_request *srq, bool *ignore_edns_size)
{
	auto answer = ldns_pkt_answer(resp);
	auto authority = ldns_pkt_authority(resp);
	
	unsigned int flags = 0;
	bool is_tcp = false;
	struct sockaddr_storage *client_addr;
	ldns_pkt *atr_pkt;
	int socket;
	bool do_atr;
	bool v4_lock;
	bool v6_lock;
	bool skip_answer = false;
	bool do_tc_only = false;
	
	
	if (srq->is_tcp == 1) {
			is_tcp = true;
	}

	// make sure there's no more than one label and extract that label
	unsigned int qname_count = ldns_dname_label_count(qname);
	if (qname_count != origin_count + 1) {
		ldns_pkt_set_rcode(resp, LDNS_RCODE_NXDOMAIN);
		return;
	}
	auto sub_label = ldns_dname_label(qname, 0);

	// make sure that label isn't a wildcard
	if (ldns_dname_is_wildcard(sub_label)) {
		ldns_pkt_set_rcode(resp, LDNS_RCODE_NXDOMAIN);
	} else {
		// check for wildcard entry
		auto rrsets = ldns_dnssec_zone_find_rrset(zone, wild, qtype);

		// copy the entry, replacing the owner name with the question
		if (rrsets) {
			// add optional stuffing before the answer here
			unsigned int prelen, pretype, postlen, posttype;
			auto p = (char *)ldns_rdf_data(sub_label) + 1;
			bool dostuff = sscanf(p, "%03x-%03x-%04x-%04x-%04x-", &prelen, &postlen, &pretype, &posttype, &flags) == 5;
			do_atr = (flags & 0x0002); // ATR is bit 2 in the flags
			// Reply if query came over IPv4, otherwise REFUSED
			v4_lock = (flags & 0x0004);
			 // Reply if query came over IPv6, otherwise REFUSED  
			v6_lock = (flags & 0x0008);
			 // Ignore EDNS bufsize sent by the client and set it our value (4096)
			*ignore_edns_size = (flags & 0x0010);
			// Jump straight to sending a TC=1 response, without the normal DNS answer
			do_tc_only = (flags & 0x0020);
			
			if (is_tcp) {
				do_atr = false; // ATR is only done for UDP queries
			}
			
			// If transport selection was specified in the experiment flags
			// (0x0004 for IPv4, 0x0006 for IPv6)
			// and the client's incoming query comes over a non-matching transport
			// reply with SRVFAIL to trigger fallback to the other transport
			
			if (srq->addr.ss_family == AF_INET && v6_lock == true) {
				ldns_pkt_set_rcode(resp, LDNS_RCODE_REFUSED);
				skip_answer = true;
			}
			if (srq->addr.ss_family == AF_INET6 && v4_lock == true) {
				ldns_pkt_set_rcode(resp, LDNS_RCODE_REFUSED);
				skip_answer = true;
			}
			
			if (do_tc_only) {
				skip_answer = true;
				do_atr = false;
				
				ldns_pkt_set_tc(resp, true);  // and turn it into a truncated,
				ldns_pkt_set_aa(resp, true);  // authoritative,
				ldns_pkt_set_ad(resp, false); // unverified,
				ldns_pkt_set_qr(resp, true);  // response
			}
			
			if (skip_answer != true) {
				// if qtype is AAAA reduce the padding by 12 bytes so that the response
				// is the same length as for an A.
				if (qtype == LDNS_RR_TYPE_AAAA) {
					if (prelen > postlen) {
						if (prelen > 12) {
							prelen -= 12;
						} else {
							prelen = 0;
						}
					} else { // postlen is the bigger one
						if (postlen > 12) {
							postlen -= 12;
						} else {
							postlen = 0;
						}
					}
				}

				if (dostuff && prelen > 0) {
					add_stuffing(answer, qname, pretype, prelen);
				}

				auto rrs = rrsets->rrs;
				while (rrs) {
					auto rr = ldns_rr_clone(rrs->rr);
					ldns_rdf_deep_free(ldns_rr_owner(rr));
					ldns_rr_set_owner(rr, ldns_rdf_clone(qname));
					ldns_rr_list_push_rr(answer, rr);
					rrs = rrs->next;
				}

				// add optional stuffing after the answer (or in other sections?)
				if (dostuff && postlen > 0) {
					add_stuffing(answer, qname, posttype, postlen);
				}
			}
		}
	}
	
	if (skip_answer != true) {
		if (do_atr) {
			int atr_index;
			client_addr = (struct sockaddr_storage *)malloc(sizeof(struct sockaddr_storage));
			memcpy(client_addr, &(srq->addr), srq->addrlen);
			atr_pkt = ldns_pkt_clone(srq->request); // Clone the query
			ldns_pkt_set_tc(atr_pkt, true);  // and turn it into a truncated,
			ldns_pkt_set_aa(atr_pkt, true);  // authoritative,
			ldns_pkt_set_ad(atr_pkt, false); // unverified,
			ldns_pkt_set_qr(atr_pkt, true);  // response
			socket = srq->socket;
			atr_index = get_first_free(); // Setup ATR delayed send
			if (atr_index >= 0) {
				makeTimer(atr_index, atr_pkt, client_addr, socket);
			} else {
				printf("Could not setup ATR. Index=%d\n",atr_index);
				free(client_addr);
				free(atr_pkt);
			}
		}		
	}

	ldns_rdf_deep_free(sub_label);
}

static void dispatch(evldns_server_request *srq, void *userdata, ldns_rdf *qname, ldns_rr_type qtype, ldns_rr_class qclass)
{
	auto handler = static_cast<SiblingZone *>(userdata);
	handler->main_callback(srq, qname, qtype);
}

struct InstanceData {
	EVLDNSBase::vfds	 vfds;
	SiblingZone			*zone;
};

static void *start_instance(void *userdata)
{
	auto data = reinterpret_cast<InstanceData *>(userdata);

	EVLDNSBase server(data->vfds);
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
	const char		*domain = "oob.dashnxdomain.net";
	const char		*zonefile = "data/zone.oob.dashnxdomain.net";
	const char		*logfile = "./queries-sibling-%F.log";

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
			case 'l': --argc; logfile = *++argv; break;
			case 'f': --argc; n_forks = atoi(*++argv); break;
			default: exit(1);
		}
		--argc;
		++argv;
	}

	SiblingZone		zone(domain, zonefile, logfile);
	InstanceData	 data = { EVLDNSBase::bind_to_all(hostnames, num_hosts, port, 100), &zone };

	farm(n_forks, n_threads, start_instance, &data, 0);

	return 0;
}
