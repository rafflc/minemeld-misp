"""
    Author: PaloAlto Minemeld, Christopher Raffl <christopher.raffl@infoguard.ch>
    Date: 20.10.2020

    This file consists of the implementation of the DataFeed class which implements all needed functionality for the
    extended TAXIIserver. The most important methods of this class are _add_indicator() (adds new indicators to
    the feed), _delete_indicator() (deletes and indicator from the feed), _age_out_run() (checks for age of indicators
    and deletes them if necessary), filtered_update() (processes updates received from the aggregator node) and
    filtered_withdraw() (processes withdraws received from the aggregator node).
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

from minemeld.ft import basepoller, base, actorbase
from minemeld.ft.utils import dt_to_millisec, interval_in_sec, utc_millisec

from mmmisp.taxiiserver.stixmapper import StixMapper


# stix_edh is imported to register the EDH data marking extensions, but it is not directly used.
# Delete the symbol to silence the warning about the import being unnecessary and prevent the
# PyCharm 'Optimize Imports' operation from removing the import.
del stix_edh

LOG = logging.getLogger(__name__)

def set_id_namespace(uri, name):
    # maec and cybox
    NS = mixbox.namespaces.Namespace(uri, name)
    mixbox.idgen.set_id_namespace(NS)


class DataFeed(actorbase.ActorBaseFT):
    def __init__(self, name, chassis, config):
        self.redis_skey = name
        self.redis_skey_value = name+'.value'
        self.redis_skey_chkp = name+'.chkp'

        self.SR = None
        self.ageout_glet = None
        self.stixMapper = StixMapper()

        super(DataFeed, self).__init__(name, chassis, config)

    def configure(self):
        """
        Configure the feed according to the specification given in the node description.
        If certain parameters are not specified, the defaults given as the second argument are used.

        :return: None
        """
        super(DataFeed, self).configure()

        self.redis_url = self.config.get('redis_url',
            os.environ.get('REDIS_URL', 'unix:///var/run/redis/redis.sock')
        )

        self.namespace = self.config.get('namespace', 'issuer')
        self.namespaceuri = self.config.get(
            'namespaceuri',
            'https://infoguard.ch'
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
        """
        Return indicator with oldest timestamp

        :return: timestamp, inidactor_id
        """
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
        """
        Processes indicator and adds it in STIX format to the TAXII output feed.

        If indicator is already present, removes it. Thus we can easily adapt new indicators and avoid
        duplication.

        :param score: int, rating of indicator (not really used)
        :param indicator: str, actual indicator
        :param value: dict, indicator object holding additional information
        :return: None
        """

        if value['type'] == 'URL':
            ind_value = werkzeug.urls.iri_to_uri(indicator, safe_conversion=True)
        else:
            ind_value = indicator

        # If indicator already exists, it gets deleted
        # By doing so, we avoid duplicates and also simplify tracking modifications.
        LOG.info("Deleting indicator " + ind_value)
        self._delete_indicator(ind_value)

        # Check if max_entries already reached. If yes, drop indicator
        if self.length() >= self.max_entries:
            LOG.info('dropped overflow')
            self.statistics['drop.overflow'] += 1
            return

        # Check if mapping for this minemeld-IoC-type exists
        if not self.stixMapper.type_exists(value['type']):
            self.statistics['drop.unknown_type'] += 1
            LOG.error('%s - Unsupported indicator type: %s', self.name, value['type'])
            return

        set_id_namespace(self.namespaceuri, self.namespace)

        # Add MetaData to IoC
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

        # create package
        spid = '{}:indicator-{}'.format(
            self.namespace,
            uuid.uuid4()
        )
        sp = stix.core.STIXPackage(id_=spid, stix_header=header)

        # Create stix indicators.
        observables = self.stixMapper.observables(self.namespace, indicator, value)

        # Iterate over created indicators, process and enrich them and add them to the package.
        # Note that the only case for which we obtain more than one is for indicators that masked an IP range.
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
                description='{} indicator from InfoGuard Threat Intel Feed. Identified as "{}"'.format(
                    value['type'],
                    value.get('misp_attribute_comment', ''),
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

            sindicator.add_indicator_type(self.stixMapper.indicator_type(value))

            sindicator.add_observable(o)

            sp.add_indicator(sindicator)

        # convert indicator to JSON and compress it
        spackage = 'lz4' + lz4.frame.compress(
            sp.to_json(),
            compression_level=lz4.frame.COMPRESSIONLEVEL_MINHC
        )

        # Adding edited indicator to storage
        LOG.info("Adding indicator again")
        with self.SR.pipeline() as p:
            p.multi()

            p.zadd(self.redis_skey, score, eindicator)
            p.hset(self.redis_skey_value, eindicator, spackage)

            result = p.execute()[0]

        self.statistics['added'] += result

    def _delete_indicator(self, indicator_id):
        """
        Removes given indicator from TAXII feed.

        :param indicator_id: str, actual value of indicator
        :return: None
        """
        with self.SR.pipeline() as p:
            p.multi()

            p.zrem(self.redis_skey, indicator_id)
            p.hdel(self.redis_skey_value, indicator_id)

            result = p.execute()[0]
            LOG.info("Removed in this iteration: " + str(result))

        self.statistics['removed'] += result

    def _age_out_run(self):
        """
        Checks for indicators that are too old and triggers their removal.

        :return: None
        """
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
        """
        Processes updates, i.e. triggers addition of new indicators.

        :param source: ignored
        :param indicator: str, actual indicator
        :param value: dict, indicator object holding additional information
        :return: None
        """
        now = utc_millisec()

        self._add_indicator(now, indicator, value)

    @base._counting('withdraw.processed')
    def filtered_withdraw(self, source=None, indicator=None, value=None):
        """
        Processes withdrawals, i.e. triggers removal of these indicators.
        :param source: ignored
        :param indicator: str, actual indicator
        :param value: dict, indicator object holding additional information
        :return: None
        """
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