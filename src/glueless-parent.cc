#include <functional>

#include "base.h"
#include "utils.h"
#include "process.h"
#include "logging.h"

class ParentHandler : public SignedBase {
private:
	ldns_rdf			*sibling;
	ldns_dnssec_rrsets	*child_nsset;

private:
	ldns_rdf *get_child(ldns_rdf *qname, unsigned int& label_count);

public:
	ParentHandler(const int *fds, const std::string& domain, const std::string& sibling, const std::string& zonefile, const std::string& keyfile);
	~ParentHandler();

public:
	void main_callback(evldns_server_request *srq, ldns_rdf *qname, ldns_rr_type qtype);
	void apex_callback(ldns_rdf *qname, ldns_rr_type qtype, bool dnssec_ok, ldns_pkt *resp);
	void referral_callback(ldns_rdf *qname, ldns_rr_type qtype, bool dnssec_ok, ldns_pkt *resp);
};

static void dispatch(evldns_server_request *srq, void *userdata, ldns_rdf *qname, ldns_rr_type qtype, ldns_rr_class qclass)
{
	ParentHandler *handler = static_cast<ParentHandler *>(userdata);
	handler->main_callback(srq, qname, qtype);
}

ParentHandler::ParentHandler(
	const int* fds,
	const std::string& domain,
	const std::string& sibling,
	const std::string& zonefile,
	const std::string& keyfile)
  : SignedBase(fds, domain, zonefile, keyfile)
{
	this->sibling = ldns_dname_new_frm_str(sibling.c_str());

	// find the wildcard NS set in the zone and remember it
	ldns_rdf *wild = ldns_dname_new_frm_str("*");
	ldns_dname_cat(wild, origin);
	child_nsset = ldns_dnssec_zone_find_rrset(zone, wild, LDNS_RR_TYPE_NS);
	ldns_rdf_deep_free(wild);
	if (!child_nsset) {
		throw std::runtime_error("zone should contain wildcard NS set");
	}

	evldns_add_callback(ev_server, NULL, LDNS_RR_CLASS_IN, LDNS_RR_TYPE_ANY, dispatch, this);
}

ParentHandler::~ParentHandler()
{
	ldns_rdf_deep_free(sibling);
}

void ParentHandler::main_callback(evldns_server_request *srq, ldns_rdf *qname, ldns_rr_type qtype)
{
	ldns_pkt *req = srq->request;
	ldns_pkt *resp = srq->response = evldns_response(req, LDNS_RCODE_NOERROR);
	ldns_rr_list *answer = ldns_pkt_answer(resp);
	ldns_rr_list *authority = ldns_pkt_authority(resp);
	bool dnssec_ok = ldns_pkt_edns_do(req);

	if (ldns_dname_compare(qname, origin) == 0) {
		apex_callback(qname, qtype, dnssec_ok, resp);
	} else if (ldns_dname_is_subdomain(qname, origin)) {
		referral_callback(qname, qtype, dnssec_ok, resp);
	} else {
		throw std::runtime_error("unreachable query code path");
	}

	ldns_pkt_set_ancount(resp, ldns_rr_list_rr_count(answer));
	ldns_pkt_set_nscount(resp, ldns_rr_list_rr_count(authority));
}

void ParentHandler::apex_callback(ldns_rdf *qname, ldns_rr_type qtype, bool dnssec_ok, ldns_pkt *resp)
{
	ldns_rr_list *answer = ldns_pkt_answer(resp);
	ldns_rr_list *authority = ldns_pkt_authority(resp);
	ldns_dnssec_rrsets *rrsets = ldns_dnssec_zone_find_rrset(zone, qname, qtype);
	if (rrsets) {
		LDNS_rr_list_cat_dnssec_rrs_clone(answer, rrsets->rrs);
		if (dnssec_ok) {
			LDNS_rr_list_cat_dnssec_rrs_clone(answer, rrsets->signatures);
		}
	} else {
		// NSEC query requires special handling
		// NB: zone requires an RR at '\000' to produce
		// the desired minimal enclosing NSEC (RFC 4470)
		if (qtype == LDNS_RR_TYPE_NSEC) {
			ldns_rr_list_push_rr(answer, ldns_rr_clone(zone->soa->nsec));
			if (dnssec_ok) {
				LDNS_rr_list_cat_dnssec_rrs_clone(answer, zone->soa->nsec_signatures);
			}
		} else {
			ldns_rr_list_push_rr(authority, ldns_rr_clone(zone->soa->nsec));
			LDNS_rr_list_cat_dnssec_rrs_clone(authority, zone->soa->rrsets->rrs);
			if (dnssec_ok) {
				LDNS_rr_list_cat_dnssec_rrs_clone(authority, zone->soa->rrsets->signatures);
				LDNS_rr_list_cat_dnssec_rrs_clone(authority, zone->soa->nsec_signatures);
			}
		}
	}

	ldns_pkt_set_aa(resp, 1);
}

void ParentHandler::referral_callback(ldns_rdf *qname, ldns_rr_type qtype, bool dnssec_ok, ldns_pkt *resp)
{
	ldns_rr_list *answer = ldns_pkt_answer(resp);
	ldns_rr_list *authority = ldns_pkt_authority(resp);

	// extract first subdomain label
	unsigned int label_count;
	ldns_rdf *child = get_child(qname, label_count);

	// there isn't really a wildcard here
	// TODO: proper NSEC denial of existence
	if (ldns_dname_is_wildcard(child)) {
		ldns_pkt_set_rcode(resp, LDNS_RCODE_REFUSED);
		ldns_rdf_deep_free(child);
		return;
	}

	// synthesize the DS record(s)
	ldns_rr_list *ds_list = ldns_rr_list_new();
	for (int i = 0, n = ldns_key_list_key_count(keys); i < n; ++i) {
		ldns_rr *key_rr = ldns_key2rr(ldns_key_list_key(keys, i));
		LDNS_rr_replace_owner(key_rr, child);
		ldns_rr *ds = ldns_key_rr2ds(key_rr, LDNS_SHA1);
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
			ldns_rr *clone = ldns_rr_clone(ns->rr);

			// replace owner
			LDNS_rr_replace_owner(clone, child);

			// replace any wildcard RDATA on above RRs
			ldns_rdf *child_label = ldns_dname_label(child, 0);
			LDNS_rr_wildcard_substitute(clone, child_label);
			ldns_rdf_deep_free(child_label);

			ldns_rr_list_push_rr(authority, clone);
			ns = ns->next;
		}

		// include DS records and RRSIGs thereof on referrals
		if (dnssec_ok) {
			ldns_rr_list_cat(authority, ds_list);
			ldns_rr_list_cat(authority, ldns_sign_public(ds_list, keys));
		}
	}
	ldns_rdf_deep_free(child);
}

ldns_rdf* ParentHandler::get_child(ldns_rdf *qname, unsigned int& label_count)
{
	unsigned int qname_count = ldns_dname_label_count(qname);
	if (qname_count <= origin_count) {
		throw std::runtime_error("impossible label count");
	}

	label_count = qname_count - origin_count;
	ldns_rdf *child = ldns_dname_clone_from(qname, label_count - 1);
}

static void *start_instance(void *userdata)
{
	Base *handler = static_cast<Base *>(userdata);
	handler->start();

	return NULL;
}

int main(int argc, char *argv[])
{
	int			n_forks = 0;
	int			n_threads = 0;
	const char	*hostname = NULL;
	const char	*port = "5053";
	const char	*domain = "tst.nxdomain.net";
	const char	*sibling = "oob.nxdomain.net";
	const char	*zonefile = "data/zone.tst.nxdomain.net";
	const char	*keyfile = "data/Ktst.nxdomain.net.+005+29517.private";

	ParentHandler handler(bind_to_all(hostname, port, 100), domain, sibling, zonefile, keyfile);

	farm(n_forks, n_threads, start_instance, &handler, 0);

	return 0;
}
