#  Copyright 2015-present Palo Alto Networks, Inc
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

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

import lz4

from minemeld.ft import basepoller, base, actorbase
from minemeld.ft.utils import dt_to_millisec, interval_in_sec, utc_millisec


# stix_edh is imported to register the EDH data marking extensions, but it is not directly used.
# Delete the symbol to silence the warning about the import being unnecessary and prevent the
# PyCharm 'Optimize Imports' operation from removing the import.
del stix_edh

LOG = logging.getLogger(__name__)

def set_id_namespace(uri, name):
    # maec and cybox
    NS = mixbox.namespaces.Namespace(uri, name)
    mixbox.idgen.set_id_namespace(NS)

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

# file.name

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
    if('windows-service-name' in value['type']):
        wo.service_name = indicator
    if('windows-service-displayname' in value['type']):
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
    if('value' in value['type']):
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
    if('.port' in value['type']):
        po = cybox.objects.port_object.Port()
        po.port_value = elems[1]
        so.port = po
    if ('hostname.' in value['type']):
        ho = cybox.objects.hostname_object.Hostname()
        ho.hostname_value = elems[0]
        so.hostname = ho
    if('IP' in value['type']):
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

_TYPE_MAPPING = {
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
        'mapper':  _stix_pipe_observable
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


class DataFeed(actorbase.ActorBaseFT):
    def __init__(self, name, chassis, config):
        self.redis_skey = name
        self.redis_skey_value = name+'.value'
        self.redis_skey_chkp = name+'.chkp'

        self.SR = None
        self.ageout_glet = None

        super(DataFeed, self).__init__(name, chassis, config)

    def configure(self):
        super(DataFeed, self).configure()

        self.redis_url = self.config.get('redis_url',
            os.environ.get('REDIS_URL', 'unix:///var/run/redis/redis.sock')
        )

        self.namespace = self.config.get('namespace', 'minemeld')
        self.namespaceuri = self.config.get(
            'namespaceuri',
            'https://go.paloaltonetworks.com/minemeld'
        )

        self.age_out_interval = self.config.get('age_out_interval', '24h')
        self.age_out_interval = interval_in_sec(self.age_out_interval)
        if self.age_out_interval < 60:
            LOG.info('%s - age out interval too small, forced to 60 seconds')
            self.age_out_interval = 60

        self.max_entries = self.config.get('max_entries', 1000 * 1000)

        self.attributes_package_title = self.config.get('attributes_package_title', [])
        if not isinstance(self.attributes_package_title, list):
            LOG.error('{} - attributes_package_title should be a list - ignored')
            self.attributes_package_title = []

        self.attributes_package_description = self.config.get('attributes_package_description', [])
        if not isinstance(self.attributes_package_description, list):
            LOG.error('{} - attributes_package_description should be a list - ignored')
            self.attributes_package_description = []

        self.attributes_package_sdescription = self.config.get('attributes_package_short_description', [])
        if not isinstance(self.attributes_package_sdescription, list):
            LOG.error('{} - attributes_package_sdescription should be a list - ignored')
            self.attributes_package_sdescription = []

        self.attributes_package_information_source = self.config.get('attributes_package_information_source', [])
        if not isinstance(self.attributes_package_information_source, list):
            LOG.error('{} - attributes_package_information_source should be a list - ignored')
            self.attributes_package_information_source = []

    def connect(self, inputs, output):
        output = False
        super(DataFeed, self).connect(inputs, output)

    def read_checkpoint(self):
        self._connect_redis()
        self.last_checkpoint = self.SR.get(self.redis_skey_chkp)

    def create_checkpoint(self, value):
        self._connect_redis()
        self.SR.set(self.redis_skey_chkp, value)

    def remove_checkpoint(self):
        self._connect_redis()
        self.SR.delete(self.redis_skey_chkp)

    def _connect_redis(self):
        if self.SR is not None:
            return

        self.SR = redis.StrictRedis.from_url(
            self.redis_url
        )

    def _read_oldest_indicator(self):
        olist = self.SR.zrange(
            self.redis_skey, 0, 0,
            withscores=True
        )
        LOG.debug('%s - oldest: %s', self.name, olist)
        if len(olist) == 0:
            return None, None

        return int(olist[0][1]), olist[0][0]

    def initialize(self):
        self._connect_redis()

    def rebuild(self):
        self._connect_redis()
        self.SR.delete(self.redis_skey)
        self.SR.delete(self.redis_skey_value)

    def reset(self):
        self._connect_redis()
        self.SR.delete(self.redis_skey)
        self.SR.delete(self.redis_skey_value)

    def _add_indicator(self, score, indicator, value):

        if value['type'] == 'URL':
            ind_value = werkzeug.urls.iri_to_uri(indicator, safe_conversion=True)
        else:
            ind_value = indicator

        self._delete_indicator(ind_value)

        if self.length() >= self.max_entries:
            LOG.info('dropped overflow')
            self.statistics['drop.overflow'] += 1
            return

        type_ = value['type']
        type_mapper = _TYPE_MAPPING.get(type_, None)
        if type_mapper is None:
            self.statistics['drop.unknown_type'] += 1
            LOG.error('%s - Unsupported indicator type: %s', self.name, type_)
            return

        set_id_namespace(self.namespaceuri, self.namespace)

        title = None
        if len(self.attributes_package_title) != 0:
            for pt in self.attributes_package_title:
                if pt not in value:
                    continue

                title = '{}'.format(value[pt])
                break

        description = None
        if len(self.attributes_package_description) != 0:
            for pd in self.attributes_package_description:
                if pd not in value:
                    continue

                description = '{}'.format(value[pd])
                break

        sdescription = None
        if len(self.attributes_package_sdescription) != 0:
            for pd in self.attributes_package_sdescription:
                if pd not in value:
                    continue

                sdescription = '{}'.format(value[pd])
                break

        information_source = None
        if len(self.attributes_package_information_source) != 0:
            for isource in self.attributes_package_information_source:
                if isource not in value:
                    continue

                information_source = '{}'.format(value[isource])
                break

            if information_source is not None:
                identity = stix.common.identity.Identity(name=information_source)
                information_source = stix.common.information_source.InformationSource(identity=identity)

        handling = None
        share_level = value.get('share_level', None)
        if share_level in ['white', 'green', 'amber', 'red']:
            marking_specification = stix.data_marking.MarkingSpecification()
            marking_specification.controlled_structure = "//node() | //@*"

            tlp = stix.extensions.marking.tlp.TLPMarkingStructure()
            tlp.color = share_level.upper()
            marking_specification.marking_structures.append(tlp)

            handling = stix.data_marking.Marking()
            handling.add_marking(marking_specification)

        header = None
        if (title is not None or
            description is not None or
            handling is not None or
            sdescription is not None or
            information_source is not None):
            header = stix.core.STIXHeader(
                title=title,
                description=description,
                handling=handling,
                short_description=sdescription,
                information_source=information_source
            )

        spid = '{}:indicator-{}'.format(
            self.namespace,
            uuid.uuid4()
        )
        sp = stix.core.STIXPackage(id_=spid, stix_header=header)

        observables = type_mapper['mapper'](self.namespace, indicator, value)

        for o in observables:
            id_ = '{}:indicator-{}'.format(
                self.namespace,
                uuid.uuid4()
            )

            if value['type'] == 'URL':
                eindicator = werkzeug.urls.iri_to_uri(indicator, safe_conversion=True)
            else:
                eindicator = indicator

            sindicator = stix.indicator.indicator.Indicator(
                id_=id_,
                title='{}: {}'.format(
                    value['type'],
                    eindicator
                ),
                description='{} indicator from InfoGuard Threat Intel Feed'.format(
                    value['type']
                ),
                timestamp=datetime.utcnow().replace(tzinfo=pytz.utc)
            )

            confidence = value.get('confidence', None)
            if confidence is None:
                LOG.error('%s - indicator without confidence', self.name)
                sindicator.confidence = "Unknown"  # We shouldn't be here
            elif confidence < 50:
                sindicator.confidence = "Low"
            elif confidence < 75:
                sindicator.confidence = "Medium"
            else:
                sindicator.confidence = "High"

            sindicator.add_indicator_type(type_mapper['indicator_type'])

            sindicator.add_observable(o)

            sp.add_indicator(sindicator)

        spackage = spackage = 'lz4'+lz4.compressHC(sp.to_json())
        with self.SR.pipeline() as p:
            p.multi()

            p.zadd(self.redis_skey, score, eindicator)
            p.hset(self.redis_skey_value, eindicator, spackage)

            result = p.execute()[0]

        self.statistics['added'] += result

    def _delete_indicator(self, indicator_id):
        with self.SR.pipeline() as p:
            p.multi()

            p.zrem(self.redis_skey, indicator_id)
            p.hdel(self.redis_skey_value, indicator_id)

            result = p.execute()[0]
            LOG.info("Removed in this iteration: " + result)

        self.statistics['removed'] += result

    def _age_out_run(self):
        while True:
            now = utc_millisec()
            low_watermark = now - self.age_out_interval*1000

            otimestamp, oindicator = self._read_oldest_indicator()
            LOG.debug(
                '{} - low watermark: {} otimestamp: {}'.format(
                    self.name,
                    low_watermark,
                    otimestamp
                )
            )
            while otimestamp is not None and otimestamp < low_watermark:
                self._delete_indicator(oindicator)
                otimestamp, oindicator = self._read_oldest_indicator()

            wait_time = 30
            if otimestamp is not None:
                next_expiration = (
                    (otimestamp + self.age_out_interval*1000) - now
                )
                wait_time = max(wait_time, next_expiration/1000 + 1)
            LOG.debug('%s - sleeping for %d secs', self.name, wait_time)

            gevent.sleep(wait_time)

    @base._counting('update.processed')
    def filtered_update(self, source=None, indicator=None, value=None):
        now = utc_millisec()

        self._add_indicator(now, indicator, value)

    @base._counting('withdraw.processed')
    def filtered_withdraw(self, source=None, indicator=None, value=None):
        LOG.info(
            self.name + "  - deleting indicator: " + indicator + ": " + str(value)
        )
        self._delete_indicator(indicator)

    def length(self, source=None):
        return self.SR.zcard(self.redis_skey)

    def start(self):
        super(DataFeed, self).start()

        self.ageout_glet = gevent.spawn(self._age_out_run)

    def stop(self):
        super(DataFeed, self).stop()

        self.ageout_glet.kill()

        LOG.info(
            "%s - # indicators: %d",
            self.name,
            self.SR.zcard(self.redis_skey)
        )

    @staticmethod
    def gc(name, config=None):
        actorbase.ActorBaseFT.gc(name, config=config)

        if config is None:
            config = {}

        redis_skey = name
        redis_skey_value = '{}.value'.format(name)
        redis_skey_chkp = '{}.chkp'.format(name)
        redis_url = config.get('redis_url',
            os.environ.get('REDIS_URL', 'unix:///var/run/redis/redis.sock')
        )

        cp = None
        try:
            cp = redis.ConnectionPool.from_url(
                redis_url
            )

            SR = redis.StrictRedis(connection_pool=cp)

            SR.delete(redis_skey)
            SR.delete(redis_skey_value)
            SR.delete(redis_skey_chkp)

        except Exception as e:
            raise RuntimeError(str(e))

        finally:
            if cp is not None:
                cp.disconnect()