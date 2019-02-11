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

#ifndef __BASE_H
#define __BASE_H

#include <string>
#include <evldns.h>
#include "evutils.h"

class EVLDNSBase {

private:
	event_base			*ev_base;
	evldns_server		*ev_server;

public:
	EVLDNSBase(const int *fds);
	~EVLDNSBase();

public:
	void add_callback(evldns_callback callback, void *userdata);
	void start();
};

class Zone {

protected:
	ldns_dnssec_zone	*zone;
	ldns_rdf			*origin;
	unsigned int		 origin_count;

public:
	Zone(const std::string& domain, const std::string& zonefile);
	~Zone();
};

class SignedZone : public Zone {

protected:
	ldns_key_list		*keys;

public:
	SignedZone(const std::string& domain, const std::string& zonefile, const std::string& keyfile);
	~SignedZone();

public:
	void sign();
};

#endif /* __BASE_H */
