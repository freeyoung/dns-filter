#!/usr/bin/env python

"""
  dns-filter.py

  A simple DNS proxy that returns NXDOMAIN if the master offers an IP from a
  specified blacklist.

  This is useful for broken ISPs that have an obnoxious and RFC-violating "The
  page you were looking for cannot be found" website for all unregistered
  domains, and you don't want to install Bind[0] or djbdns[1].

  See also [2] [3] [4].

     [0] http://www.isc.org/sw/bind/
     [1] http://cr.yp.to/djbdns.htmle
     [2] http://www.nanog.org/mtg-0310/pdf/woolf.pdf (PDF slides)
     [3] http://en.wikipedia.org/wiki/Wildcard_DNS_record
     [4] http://en.wikipedia.org/wiki/Site_Finder

  Additionally, this program can also strip unwanted A records from the
  responses returned by upstream.

  Another feature called "screened domains" is supported, with which this
  program can screen specified domains per given src-subnets.

   Copyright (C) 2007  Chris Lamb <chris@chris-lamb.co.uk>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import os
import sys
import json
import socket

from netaddr import IPNetwork, IPAddress
from twisted.names import client, server, dns, error, resolve
from twisted.python import failure
from twisted.application import service, internet
from twisted.internet import defer


typeToMethod = {
    dns.A:     'lookupAddress',
    dns.AAAA:  'lookupIPV6Address',
    dns.A6:    'lookupAddress6',
    dns.NS:    'lookupNameservers',
    dns.CNAME: 'lookupCanonicalName',
    dns.SOA:   'lookupAuthority',
    dns.MB:    'lookupMailBox',
    dns.MG:    'lookupMailGroup',
    dns.MR:    'lookupMailRename',
    dns.NULL:  'lookupNull',
    dns.WKS:   'lookupWellKnownServices',
    dns.PTR:   'lookupPointer',
    dns.HINFO: 'lookupHostInfo',
    dns.MINFO: 'lookupMailboxInfo',
    dns.MX:    'lookupMailExchange',
    dns.TXT:   'lookupText',
    dns.SPF:   'lookupSenderPolicy',

    dns.RP:    'lookupResponsibility',
    dns.AFSDB: 'lookupAFSDatabase',
    dns.SRV:   'lookupService',
    dns.NAPTR: 'lookupNamingAuthorityPointer',
    dns.AXFR:         'lookupZone',
    dns.ALL_RECORDS:  'lookupAllRecords',
}


queryWithAddr = (
    'lookupAddress',
)


config_file = os.environ.get("DNS_FILTER_CONF", "/etc/dns-filter.json")

try:
    with open(config_file, "r") as f:
        config = json.load(f)
except IOError:
    print "Config file not found."
    sys.exit(2)
except ValueError:
    print "Failed to parse config file."
    sys.exit(1)


class FailureHandler:
    def __init__(self, resolver, query, timeout, addr=None):
        self.resolver = resolver
        self.query = query
        self.timeout = timeout
        self.addr = addr

    def __call__(self, failure):
        # AuthoritativeDomainErrors should halt resolution attempts
        failure.trap(error.DomainError, defer.TimeoutError, NotImplementedError)
        return self.resolver(self.query, self.timeout, self.addr)


class MyResolver(client.Resolver):
    def query(self, query, timeout=None, addr=None):
        try:
            if typeToMethod[query.type] in queryWithAddr:
                return self.typeToMethod[query.type](str(query.name), timeout, addr)
            else:
                return self.typeToMethod[query.type](str(query.name), timeout)
        except KeyError:
            return defer.fail(failure.Failure(NotImplementedError(str(self.__class__) + " " + str(query.type))))

    def lookupAddress(self, name, timeout=None, addr=None):
        if self.screened:
            for subnet in self.screened:
                if IPAddress(addr) in IPNetwork(subnet) and name in self.screened[subnet]:
                    return defer.fail(error.DomainError())
        return self._lookup(name, dns.IN, dns.A, timeout)

    def filterAnswers(self, x):
        if x.trunc:
            return self.queryTCP(x.queries).addCallback(self.filterAnswers)

        if x.rCode != dns.OK:
            f = self._errormap.get(x.rCode, error.DNSUnknownError)(x)
            return failure.Failure(f)

        for y in x.answers:
            # We're only interested in 'A' records
            if not isinstance(y.payload, dns.Record_A):
                continue

            # Strip unwanted IPs
            if y.payload.dottedQuad() in self.stripped:
                x.answers.remove(y)
                continue

            # Report failure if we encounter one of the invalid
            if y.payload.dottedQuad() in self.invalid:
                f = self._errormap.get(x.rCode, error.DomainError)(x)
                return failure.Failure(f)

        return (x.answers, x.authority, x.additional)


class MyResolverChain(resolve.ResolverChain):

    def _lookup(self, name, cls, type, timeout, addr=None):
        if not self.resolvers:
            return defer.fail(dns.DomainError())
        q = dns.Query(name, type, cls)
        d = self.resolvers[0].query(q, timeout, addr)
        for r in self.resolvers[1:]:
            d = d.addErrback(
                FailureHandler(r.query, q, timeout, addr)
            )
        return d

    def query(self, query, timeout=None, addr=None):
        try:
            if typeToMethod[query.type] in queryWithAddr:
                return self.typeToMethod[query.type](str(query.name), timeout, addr)
            else:
                return self.typeToMethod[query.type](str(query.name), timeout)
        except KeyError:
            return defer.fail(failure.Failure(NotImplementedError(str(self.__class__) + " " + str(query.type))))

    def lookupAddress(self, name, timeout=None, addr=None):
        return self._lookup(name, dns.IN, dns.A, timeout, addr)


class MyDNSServerFactory(server.DNSServerFactory):
    def handleQuery(self, message, protocol, address):
        query = message.queries[0]
        cliAddr = address[0]

        if typeToMethod[query.type] in queryWithAddr and message.additional:
            additional_rr = message.additional[0]
            if additional_rr.type == 41 and additional_rr.rdlength > 8:
                cliAddr = socket.inet_ntoa(additional_rr.payload.data[-4:])

        return self.resolver.query(query, addr=cliAddr).addCallback(
            self.gotResolverResponse, protocol, message, address
        ).addErrback(
            self.gotResolverError, protocol, message, address
        )

    def __init__(self, authorities=None, caches=None, clients=None, verbose=0):
        resolvers = []
        if authorities is not None:
            resolvers.extend(authorities)
        if caches is not None:
            resolvers.extend(caches)
        if clients is not None:
            resolvers.extend(clients)

        self.canRecurse = not not clients
        self.resolver = MyResolverChain(resolvers)
        self.verbose = verbose
        if caches:
            self.cache = caches[-1]
        self.connections = []


# Configure our custom resolver
resolver = MyResolver(servers=[(config['server']['upstream']['host'],
                                config['server']['upstream']['port'])])
resolver.invalid = config['rules']['invalid']
resolver.stripped = config['rules']['stripped']
resolver.screened = config['rules']['screened']

factory = MyDNSServerFactory(clients=[resolver])
protocol = dns.DNSDatagramProtocol(factory)

dnsFilterService = internet.UDPServer(
    config['server']['listen']['port'],
    protocol,
    config['server']['listen']['host'],
)
application = service.Application("DNS filter")
dnsFilterService.setServiceParent(application)
