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

#include "evutils.h"
#include "utils.h"

void query_check(evldns_server_request *srq,
				 ATTR_UNUSED(void *user_data),
				 ATTR_UNUSED(ldns_rdf *qname),
				 ldns_rr_type qtype,
				 ldns_rr_class qclass)
{
	ldns_pkt *req = srq->request;

	/* only QUERY is supported */
	if (ldns_pkt_get_opcode(req) != LDNS_PACKET_QUERY) {
		srq->response = evldns_response(req, LDNS_RCODE_NOTIMPL);
		return;
	}

	/* QDCOUNT == 1, NB: QR == 1 now handled upstream */
	if (ldns_pkt_qdcount(req) != 1) {
		srq->response = evldns_response(req, LDNS_RCODE_FORMERR);
		return;
	}

	/* Unexpected QCLASS */
	if (qclass != LDNS_RR_CLASS_IN) {
		srq->response = evldns_response(req, LDNS_RCODE_NOTIMPL);
		return;
	}

	/* Unexpected QTYPE */
	if (qtype == LDNS_RR_TYPE_AXFR || qtype == LDNS_RR_TYPE_IXFR) {
		srq->response = evldns_response(req, LDNS_RCODE_NOTIMPL);
		return;
	}

	/* Not going to handle QTYPE == ANY either */
	if (qtype == LDNS_RR_TYPE_ANY) {
		srq->response = evldns_response(req, LDNS_RCODE_NOTIMPL);
		return;
	}
}

void truncation_check(evldns_server_request *srq, bool ignore_edns_size)
{
	ldns_pkt *req = srq->request;
	ldns_pkt *resp = srq->response;
	unsigned int bufsize = 512;

	/* if it's TCP, business as usual */
	if (srq->is_tcp) {
		return;
	}

	/* otherwise, convert to wire format, if necessary */
	if (!srq->wire_response) {
		(void) ldns_pkt2wire(&srq->wire_response, resp, &srq->wire_resplen);
	}

	/* if it's under the RFC 1035 limit, we're OK */
	if (srq->wire_resplen <= bufsize) {
		return;
	}

  // Temporary hack to limit response size on UDP
  // If the response size is under 1280, do the EDNS checks.
  // Otherwise go to truncation
		// if (srq->wire_resplen <= 1280) {
	/* if the client used EDNS, use that new bufsize */
	if (ldns_pkt_edns(req)) {
		unsigned int ednssize = ldns_pkt_edns_udp_size(req);
		if (ignore_edns_size) {
			bufsize = 4096;
		} else if (ednssize > bufsize) {
			bufsize = ednssize;
		}

		/* it fits - we're OK */
		if (srq->wire_resplen <= bufsize) {
			return;
		}
  	}
  // }

	/*
	 * if we got here, it didn't fit - throw away the
	 * existing wire buffer and the non-question sections
	 */
	free(srq->wire_response);
	LDNS_rr_list_empty_rr_list(ldns_pkt_additional(resp));
	LDNS_rr_list_empty_rr_list(ldns_pkt_authority(resp));
	LDNS_rr_list_empty_rr_list(ldns_pkt_answer(resp));

	/* set the TC bit and reset section counts */
	ldns_pkt_set_tc(resp, true);
	ldns_pkt_set_ancount(resp, 0);
	ldns_pkt_set_nscount(resp, 0);
	ldns_pkt_set_arcount(resp, 0);

	/* and convert to wire format again */
	(void) ldns_pkt2wire(&srq->wire_response, resp, &srq->wire_resplen);
}
