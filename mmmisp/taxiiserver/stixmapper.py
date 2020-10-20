"""
    Author: PaloAlto Minemeld, Christopher Raffl <christopher.raffl@infoguard.ch>
    Date: 20.10.2020

    This file consists of two things. Firs, a class StixMapper that maps types as they are used in Minemeld to
    stix-types. Second, for each mapping there exists a method that takes care of creating a stix/cybox object
    in such a form that it can be added to the TAXII datafeeed.

"""

from __future__ import absolute_import

import logging
import copy
import urlparse
import uuid
import os.path
from datetime import datetime, timedelta

import pytz
import lxml.etree
import yaml
import redis
import gevent
import gevent.event
import netaddr
import werkzeug.urls
from six import string_types

import libtaxii
import libtaxii.clients
import libtaxii.messages_11
from libtaxii.constants import MSG_STATUS_MESSAGE, ST_SUCCESS

import stix.core.stix_package
import stix.core.stix_header
import stix.indicator
import stix.common.vocabs
import stix.common.information_source
import stix.common.identity
import stix.extensions.marking.ais
import stix.data_marking
import stix.extensions.marking.tlp

import stix_edh

import cybox.core
import cybox.objects.address_object
import cybox.objects.domain_name_object
import cybox.objects.uri_object
import cybox.objects.file_object
import cybox.objects.mutex_object
import cybox.objects.pipe_object
import cybox.objects.port_object
import cybox.objects.win_service_object
import cybox.objects.win_registry_key_object
import cybox.objects.hostname_object
import cybox.objects.socket_address_object
import cybox.objects.whois_object

import mixbox.idgen
import mixbox.namespaces

import lz4.frame


class StixMapper():
    def __init__(self):
        # Mapping of minemeld IoC types to stix indicator types and methods that create STIX/cybox objects for
        # the given Minemeld type.
        self._TYPE_MAPPING = {
            'IPv4': {
                'indicator_type': stix.common.vocabs.IndicatorType.TERM_IP_WATCHLIST,
                'mapper': _stix_ip_observable
            },
            'IPv6': {
                'indicator_type': stix.common.vocabs.IndicatorType.TERM_IP_WATCHLIST,
                'mapper': _stix_ip_observable
            },
            'URL': {
                'indicator_type': stix.common.vocabs.IndicatorType.TERM_URL_WATCHLIST,
                'mapper': _stix_url_observable
            },
            'domain': {
                'indicator_type': stix.common.vocabs.IndicatorType.TERM_DOMAIN_WATCHLIST,
                'mapper': _stix_domain_observable
            },
            'sha256': {
                'indicator_type': stix.common.vocabs.IndicatorType.TERM_FILE_HASH_WATCHLIST,
                'mapper': _stix_hash_observable
            },
            'sha512': {
                'indicator_type': stix.common.vocabs.IndicatorType.TERM_FILE_HASH_WATCHLIST,
                'mapper': _stix_hash_observable
            },
            'sha1': {
                'indicator_type': stix.common.vocabs.IndicatorType.TERM_FILE_HASH_WATCHLIST,
                'mapper': _stix_hash_observable
            },
            'md5': {
                'indicator_type': stix.common.vocabs.IndicatorType.TERM_FILE_HASH_WATCHLIST,
                'mapper': _stix_hash_observable
            },
            'ssdeep': {
                'indicator_type': stix.common.vocabs.IndicatorType.TERM_FILE_HASH_WATCHLIST,
                'mapper': _stix_hash_observable
            },
            'email': {
                'indicator_type': stix.common.vocabs.IndicatorType.TERM_MALICIOUS_EMAIL,
                'mapper': _stix_email_addr_observable
            },
            'file.name': {
                'indicator_type': stix.common.vocabs.IndicatorType.TERM_MALWARE_ARTIFACTS,
                'mapper': _stix_filename_observable
            },
            'file.name.md5': {
                'indicator_type': stix.common.vocabs.IndicatorType.TERM_FILE_HASH_WATCHLIST,
                'mapper': _stix_filename_hash_observable
            },
            'file.name.sha1': {
                'indicator_type': stix.common.vocabs.IndicatorType.TERM_FILE_HASH_WATCHLIST,
                'mapper': _stix_filename_hash_observable
            },
            'file.name.sha256': {
                'indicator_type': stix.common.vocabs.IndicatorType.TERM_FILE_HASH_WATCHLIST,
                'mapper': _stix_filename_hash_observable
            },
            'file.name.sha512': {
                'indicator_type': stix.common.vocabs.IndicatorType.TERM_FILE_HASH_WATCHLIST,
                'mapper': _stix_filename_hash_observable
            },
            'file.name.ssdeep': {
                'indicator_type': stix.common.vocabs.IndicatorType.TERM_FILE_HASH_WATCHLIST,
                'mapper': _stix_filename_hash_observable
            },
            'mutex': {
                'indicator_type': stix.common.vocabs.IndicatorType.TERM_MALWARE_ARTIFACTS,
                'mapper': _stix_mutex_observable
            },
            'pipe': {
                'indicator_type': stix.common.vocabs.IndicatorType.TERM_MALWARE_ARTIFACTS,
                'mapper': _stix_pipe_observable
            },
            'port': {
                'indicator_type': stix.common.vocabs.IndicatorType.TERM_HOST_CHARACTERISTICS,
                'mapper': _stix_port_observable
            },
            'windows-service-displayname': {
                'indicator_type': stix.common.vocabs.IndicatorType.TERM_MALWARE_ARTIFACTS,
                'mapper': _stix_windows_service_observable
            },
            'windows-service-name': {
                'indicator_type': stix.common.vocabs.IndicatorType.TERM_MALWARE_ARTIFACTS,
                'mapper': _stix_windows_service_observable
            },
            'regkey': {
                'indicator_type': stix.common.vocabs.IndicatorType.TERM_MALWARE_ARTIFACTS,
                'mapper': _stix_registry_key_observable
            },
            'regkey.value': {
                'indicator_type': stix.common.vocabs.IndicatorType.TERM_MALWARE_ARTIFACTS,
                'mapper': _stix_registry_key_observable
            },
            'hostname.port': {
                'indicator_type': stix.common.vocabs.IndicatorType.TERM_HOST_CHARACTERISTICS,
                'mapper': _stix_socket_observable
            },
            'IPv4.port': {
                'indicator_type': stix.common.vocabs.IndicatorType.TERM_HOST_CHARACTERISTICS,
                'mapper': _stix_socket_observable
            },
            'IPv6.port': {
                'indicator_type': stix.common.vocabs.IndicatorType.TERM_HOST_CHARACTERISTICS,
                'mapper': _stix_socket_observable
            },
            'hostname': {
                'indicator_type': stix.common.vocabs.IndicatorType.TERM_DOMAIN_WATCHLIST,
                'mapper': _stix_hostname_observable
            },
            'domain.IPv4': {
                'indicator_type': stix.common.vocabs.IndicatorType.TERM_IP_WATCHLIST,
                'mapper': _stix_whois_observable
            },
            'domain.IPv6': {
                'indicator_type': stix.common.vocabs.IndicatorType.TERM_IP_WATCHLIST,
                'mapper': _stix_whois_observable
            }
        }

    def type_exists(self, type):
        return self._TYPE_MAPPING.get(type, None) is not None

    def observables(self, namespace, indicator, value):
        type = self._TYPE_MAPPING.get(value['type'])
        return type['mapper'](namespace, indicator, value)

    def indicator_type(self, value):
        return self._TYPE_MAPPING.get(value['type'])['indicator_type']


# IPv4, IPv6
def _stix_ip_observable(namespace, indicator, value):
    category = cybox.objects.address_object.Address.CAT_IPV4
    if value['type'] == 'IPv6':
        category = cybox.objects.address_object.Address.CAT_IPV6

    indicators = [indicator]
    if '-' in indicator:
        # looks like an IP Range, let's try to make it a CIDR
        a1, a2 = indicator.split('-', 1)
        if a1 == a2:
            # same IP
            indicators = [a1]
        else:
            # use netaddr builtin algo to summarize range into CIDR
            iprange = netaddr.IPRange(a1, a2)
            cidrs = iprange.cidrs()
            indicators = map(str, cidrs)

    observables = []
    for i in indicators:
        id_ = '{}:observable-{}'.format(
            namespace,
            uuid.uuid4()
        )

        ao = cybox.objects.address_object.Address(
            address_value=i,
            category=category
        )

        o = cybox.core.Observable(
            title='{}: {}'.format(value['type'], i),
            id_=id_,
            item=ao
        )

        observables.append(o)

    return observables


# email
def _stix_email_addr_observable(namespace, indicator, value):
    category = cybox.objects.address_object.Address.CAT_EMAIL

    id_ = '{}:observable-{}'.format(
        namespace,
        uuid.uuid4()
    )

    ao = cybox.objects.address_object.Address(
        address_value=indicator,
        category=category
    )

    o = cybox.core.Observable(
        title='{}: {}'.format(value['type'], indicator),
        id_=id_,
        item=ao
    )

    return [o]


# domain
def _stix_domain_observable(namespace, indicator, value):
    id_ = '{}:observable-{}'.format(
        namespace,
        uuid.uuid4()
    )

    do = cybox.objects.domain_name_object.DomainName()
    do.value = indicator
    do.type_ = 'FQDN'

    o = cybox.core.Observable(
        title='FQDN: ' + indicator,
        id_=id_,
        item=do
    )

    return [o]


# URL
def _stix_url_observable(namespace, indicator, value):
    id_ = '{}:observable-{}'.format(
        namespace,
        uuid.uuid4()
    )

    uo = cybox.objects.uri_object.URI(
        value=indicator,
        type_=cybox.objects.uri_object.URI.TYPE_URL
    )

    o = cybox.core.Observable(
        title='URL: ' + indicator,
        id_=id_,
        item=uo
    )

    return [o]


# md5, sha1, sha256, sha512, ssdeep
def _stix_hash_observable(namespace, indicator, value):
    id_ = '{}:observable-{}'.format(
        namespace,
        uuid.uuid4()
    )

    uo = cybox.objects.file_object.File()
    # add_hash automatically detects type of hash using the length of the given
    # parameter. Currently ssdeep hashes are not correctly supported by the library
    uo.add_hash(indicator)

    o = cybox.core.Observable(
        title='{}: {}'.format(value['type'], indicator),
        id_=id_,
        item=uo
    )

    return [o]


# file.name.md5, file.name.sha1, file.name.sha256, file.name.ssdeep, file.name.sha512
def _stix_filename_hash_observable(namespace, indicator, value):
    id_ = '{}:observable-{}'.format(
        namespace,
        uuid.uuid4()
    )

    splitted = indicator.split('|')
    filename = splitted[0]
    hash = splitted[1]

    uo = cybox.objects.file_object.File()
    # add_hash automatically detects type of hash using the length of the given
    # parameter. Currently ssdeep hashes are not correctly supported by the library
    uo.add_hash(hash)
    uo.file_name = filename

    o = cybox.core.Observable(
        title='{}: {}'.format(value['type'], indicator),
        id_=id_,
        item=uo
    )

    return [o]


# file.nameq
def _stix_filename_observable(namespace, indicator, value):
    id_ = '{}:observable-{}'.format(
        namespace,
        uuid.uuid4()
    )

    uo = cybox.objects.file_object.File()
    uo.file_name = indicator

    o = cybox.core.Observable(
        title='{}: {}'.format(value['type'], indicator),
        id_=id_,
        item=uo
    )

    return [o]


# mutex
def _stix_mutex_observable(namespace, indicator, value):
    id_ = '{}:observable-{}'.format(
        namespace,
        uuid.uuid4()
    )

    mo = cybox.objects.mutex_object.Mutex()
    mo.name = indicator

    o = cybox.core.Observable(
        title='{}: {}'.format(value['type'], indicator),
        id_=id_,
        item=mo
    )

    return [o]


# pipe
def _stix_pipe_observable(namespace, indicator, value):
    id_ = '{}:observable-{}'.format(
        namespace,
        uuid.uuid4()
    )

    po = cybox.objects.pipe_object.Pipe()
    po.name = indicator

    o = cybox.core.Observable(
        title='{}: {}'.format(value['type'], indicator),
        id_=id_,
        item=po
    )

    return [o]


# port
def _stix_port_observable(namespace, indicator, value):
    id_ = '{}:observable-{}'.format(
        namespace,
        uuid.uuid4()
    )

    po = cybox.objects.port_object.Port()
    po.port_value = indicator

    o = cybox.core.Observable(
        title='{}: {}'.format(value['type'], indicator),
        id_=id_,
        item=po
    )

    return [o]


# windows-service-displayname, windows-service-name
def _stix_windows_service_observable(namespace, indicator, value):
    id_ = '{}:observable-{}'.format(
        namespace,
        uuid.uuid4()
    )

    wo = cybox.objects.win_service_object.WinService()
    if ('windows-service-name' in value['type']):
        wo.service_name = indicator
    if ('windows-service-displayname' in value['type']):
        wo.display_name = indicator

    o = cybox.core.Observable(
        title='{}: {}'.format(value['type'], indicator),
        id_=id_,
        item=wo
    )

    return [o]


# regkey, regkey.value
def _stix_registry_key_observable(namespace, indicator, value):
    id_ = '{}:observable-{}'.format(
        namespace,
        uuid.uuid4()
    )

    ro = cybox.objects.win_registry_key_object.WinRegistryKey()
    if 'value' in value['type']:
        elems = indicator.split('|')
        ro.key = elems[0]
        vo = cybox.objects.win_registry_key_object.RegistryValue()
        vo.name = elems[1]
        ro.values = cybox.objects.win_registry_key_object.RegistryValues()
        ro.values.value = [vo]
    else:
        ro.key = indicator

    o = cybox.core.Observable(
        title='{}: {}'.format(value['type'], indicator),
        id_=id_,
        item=ro
    )

    return [o]


# hostname
def _stix_hostname_observable(namespace, indicator, value):
    id_ = '{}:observable-{}'.format(
        namespace,
        uuid.uuid4()
    )

    ho = cybox.objects.hostname_object.Hostname()
    ho.hostname_value = indicator

    o = cybox.core.Observable(
        title='{}: {}'.format(value['type'], indicator),
        id_=id_,
        item=ho
    )

    return [o]


# hostname.port, IPv4.port, IPv6.port
def _stix_socket_observable(namespace, indicator, value):
    id_ = '{}:observable-{}'.format(
        namespace,
        uuid.uuid4()
    )

    so = cybox.objects.socket_address_object.SocketAddress()
    elems = indicator.split('|')
    if ('.port' in value['type']):
        po = cybox.objects.port_object.Port()
        po.port_value = elems[1]
        so.port = po
    if ('hostname.' in value['type']):
        ho = cybox.objects.hostname_object.Hostname()
        ho.hostname_value = elems[0]
        so.hostname = ho
    if ('IP' in value['type']):
        category = cybox.objects.address_object.Address.CAT_IPV4
        if ('IPv6' in value['type']):
            category = cybox.objects.address_object.Address.CAT_IPV6

        indicators = [elems[0]]
        if '-' in indicator:
            # looks like an IP Range, let's try to make it a CIDR
            a1, a2 = elems[0].split('-', 1)
            if a1 == a2:
                # same IP
                indicators = [a1]
            else:
                # use netaddr builtin algo to summarize range into CIDR
                iprange = netaddr.IPRange(a1, a2)
                cidrs = iprange.cidrs()
                indicators = map(str, cidrs)

        ao = cybox.objects.address_object.Address(
            address_value=indicators[0],
            category=category
        )

        so.ip_address = ao

    o = cybox.core.Observable(
        title='{}: {}'.format(value['type'], indicator),
        id_=id_,
        item=so
    )

    return [o]


# domain.IPv4, domain.IPv6
def _stix_whois_observable(namespace, indicator, value):
    id_ = '{}:observable-{}'.format(
        namespace,
        uuid.uuid4()
    )

    elems = indicator.split('|')
    wo = cybox.objects.whois_object.WhoisEntry()
    wo.domain_name = cybox.objects.uri_object.URI(
        value=elems[0]
    )

    category = cybox.objects.address_object.Address.CAT_IPV4
    if ('IPv6' in value['type']):
        category = cybox.objects.address_object.Address.CAT_IPV6

    indicators = [elems[1]]
    if '-' in indicator:
        # looks like an IP Range, let's try to make it a CIDR
        a1, a2 = elems[1].split('-', 1)
        if a1 == a2:
            # same IP
            indicators = [a1]
        else:
            # use netaddr builtin algo to summarize range into CIDR
            iprange = netaddr.IPRange(a1, a2)
            cidrs = iprange.cidrs()
            indicators = map(str, cidrs)

    ao = cybox.objects.address_object.Address(
        address_value=indicators[0],
        category=category
    )

    wo.ip_address = ao

    o = cybox.core.Observable(
        title='{}: {}'.format(value['type'], indicator),
        id_=id_,
        item=wo
    )

    return [o]
