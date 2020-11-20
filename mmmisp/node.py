"""
    Author: Creator of the MISP-extension, Christopher Raffl <christopher.raffl@infoguard.ch>
    Date: 20.10.2020

    This file consists of the implementation of the Miner class which implements all needed functionality for the
    MISP-Miner nodes. The most important methods of this class are _build_iterator() (responsible for requesting
    events and their attributes from MISP via its API) and _process_item() (responsible for processing the answer
    propagate IoCs according to the configuration).
"""

import logging
import os
import re
import copy
from functools import partial
from itertools import imap
from datetime import datetime
import time

import yaml
import jmespath
from netaddr import IPNetwork, AddrFormatError
from pymisp import PyMISP
from minemeld.ft.basepoller import BasePollerFT

LOG = logging.getLogger(__name__)

# Mapping of MISP types to Minemeld types
_MISP_TO_MINEMELD = {
    'url': 'URL',
    'domain': 'domain',
    'domain|ip': 'domain.ip',
    'hostname': 'hostname',
    'hostname|port': 'hostname.port',
    'md5': 'md5',
    'sha256': 'sha256',
    'sha1': 'sha1',
    'sha512': 'sha512',
    'ssdeep': 'ssdeep',
    'mutex': 'mutex',
    'filename': 'file.name',
    'filename|md5': 'file.name.md5',
    'filename|sha1': 'file.name.sha1',
    'filename|sha256': 'file.name.sha256',
    'filename|sha512': 'file.name.sha512',
    'filename|ssdeep': 'file.name.ssdeep',
    'email-src': 'email',
    'email-dst': 'email',
    'named pipe': 'pipe',
    'port': 'port',
    'windows-service-displayname': 'windows-service-displayname',
    'windows-service-name': 'windows-service-name',
    'regkey': 'regkey',
    'regkey|value': 'regkey.value',
}

class Miner(BasePollerFT):
    def __init__(self, name, chassis, config):
        self.automation_key = None
        self.url = None
        self.verify_cert = True

        self.datefrom_re = re.compile('^([0-9]+)d$')

        super(Miner, self).__init__(name, chassis, config)

    def configure(self):
        """
        Configure the miner according to the specification given in the node description.
        If certain parameters are not specified, the defaults given as the second argument are used.

        :return: None
        """
        super(Miner, self).configure()

        self.interval = self.config.get('interval', 600)

        self.prefix = self.config.get('prefix', 'misp')
        self.indicator_types = self.config.get('indicator_types', None)

        self.url = self.config.get('url', None)
        self.filters = self.config.get('filters', None)

        # option for enabling client cert, default disabled
        self.client_cert_required = self.config.get('client_cert_required', False)
        if self.client_cert_required:
            self.key_file = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '%s.pem' % self.name
            )
            self.cert_file = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '%s.crt' % self.name
            )

        self.honour_ids_flag = self.config.get('honour_ids_flag', True)

        teventattrs = self.config.get(
            'event_attributes',
            dict(
                info='info',
                org='Org.name',
                orgc='Orgc.name',
                threat_level_id='threat_level_id',
                tags='Tag[*].name',
                uuid='uuid'
            )
        )
        self.event_attributes = {}
        for aname, aexpr in teventattrs.iteritems():
            self.event_attributes[aname] = jmespath.compile(aexpr)

        tattrattributes = self.config.get(
            'attribute_attributes',
            dict(
                uuid='uuid',
                category='category',
                comment='comment',
                tags='Tag[*].name'
            )
        )
        self.attribute_attributes = {}
        for aname, aexpr in tattrattributes.iteritems():
            self.attribute_attributes[aname] = jmespath.compile(aexpr)

        self.side_config_path = self.config.get('side_config', None)
        if self.side_config_path is None:
            self.side_config_path = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '%s_side_config.yml' % self.name
            )

        self._load_side_config()

    def _load_side_config(self):
        """
        Configure the miner according to the specification given by the user via the UI.
        :return: None
        """
        try:
            with open(self.side_config_path, 'r') as f:
                sconfig = yaml.safe_load(f)

        except Exception as e:
            LOG.error('%s - Error loading side config: %s', self.name, str(e))
            return

        self.automation_key = sconfig.get('automation_key', None)
        self.verify_cert = sconfig.get('verify_cert', True)

        turl = sconfig.get('url', None)
        if turl is not None:
            self.url = turl
            LOG.info('{} - url set'.format(self.name))

    def _load_event(self, misp, event):
        """
        Given MISP connection and an event index, query API for corresponding event

        :param misp: MISP connection
        :param event: Index containing uuid of event
        :return: Answer of the MISP-API containing the requested event
        """
        euuid = event.get('uuid', None)
        if euuid is None:
            LOG.error('{} - event with no uuid: {!r}'.format(self.name, event))
            return None

        return misp.get(event['uuid'])

    def _build_iterator(self, now):
        """
        Queries specified MISP instance to get events, filter them according to given filters and returns events.

        :param now: unused
        :return: itarable. Holds the events returned by the API that matched the given filters.
        """

        # Sanity checks
        if self.automation_key is None:
            raise RuntimeError('{} - MISP Automation Key not set'.format(self.name))

        if self.url is None:
            raise RuntimeError('{} - MISP URL not set'.format(self.name))

        kwargs = {'ssl': self.verify_cert}
        if self.verify_cert and 'REQUESTS_CA_BUNDLE' in os.environ:
            kwargs['ssl'] = os.environ['REQUESTS_CA_BUNDLE']

        if self.client_cert_required:
            kwargs['cert'] = (self.cert_file, self.key_file)

        # Establish API connection
        misp = PyMISP(self.url, self.automation_key, **kwargs)

        filters = None
        if self.filters is not None:
            # Map self.filters in the way they are given by the configuration to the way they are required in order
            # to actually filter the events returned by the API.
            filters = self.filters.copy()
            if 'datefrom' in filters:
                filters['timestamp'] = filters.pop('datefrom')

            du = filters.pop('dateuntil', None)
            if du is not None:
                filters['dateuntil'] = du
            if 'event_tags' in filters and filters['event_tags']:
                filters['tags'] = [x.strip() for x in filters['event_tags'].split(",")]

        LOG.info('{} - query filters: {!r}'.format(self.name, filters))

        # Get index from all events via API matching the given filter
        r = misp.get_index(filters)

        events = r['response']

        return imap(partial(self._load_event, misp), events)

    def _detect_ip_version(self, ip_addr):
        """
        Given an IP-address, returns if it is IPv4, IPv6 or invalid

        :param ip_addr: String. Containing IP-adress
        :return: String. Indicate version if correct IP else, None
        """
        try:
            parsed = IPNetwork(ip_addr)
        except (AddrFormatError, ValueError):
            LOG.error('{} - Unknown IP version: {}'.format(self.name, ip_addr))
            return None

        if parsed.version == 4:
            return 'IPv4'

        if parsed.version == 6:
            return 'IPv6'

        return None

    def _process_item(self, event):
        """
        Processes all attributes of an event matching the filters and returns them in minemeld-format.

        :param event: MISP-event returned by API
        :return: list containing of attributes (=IoCs)
        """
        event = event.get('Event', None)
        if event is None:
            return []

        result = []

        base_value = {}
        for aname, aexpr in self.event_attributes.iteritems():
            try:
                eresult = aexpr.search(event)
            except:
                continue

            if eresult is None:
                continue

            base_value['{}_event_{}'.format(self.prefix, aname)] = eresult

        attributes = event.get('Attribute', [])

        # Get timestamp of "datefrom" filter
        if self.filters is not None and 'datefrom' in self.filters:
            now = int(time.time())
            limit = now - 86400 * int(self.filters['datefrom'][:-1])

        # Iterate over all attributes
        for a in attributes:
            LOG.info('{} - New attribute: {!r}'.format(self.name, a))
            # check if timestamp is older than "datefrom" filter
            if self.filters is not None and 'datefrom' in self.filters:
                last_edited = int(a.get('timestamp', None))
                if limit > last_edited:
                    LOG.info("Entry too old - discarded")
                    continue
            # Get tlp from attribute and set it as the share level
            tags = a.get('Tag', [])
            attribute_tags = []
            for t in tags:
                tname = t.get('name', None)
                LOG.info('Found tag ' + tname)
                if tname is None:
                    continue
                attribute_tags.append(tname)

                if tname.startswith('tlp:'):
                    filter_tag = tname
                    base_value['share_level'] = tname[4:]

            drop = False
            # Check if the attributes tag matches the given filters,
            if 'attribute_tags' in self.filters:
                tags = [x.strip() for x in self.filters['attribute_tags'].split(",")]
                LOG.info('Attribute tags: ' + str(attribute_tags))
                for tag in tags:
                    if tag.startswith('!'):
                        if tag[1:] in attribute_tags:
                            drop = True
                    else:
                        if tag not in attribute_tags:
                            LOG.info('Not found: ' + tag)
                            drop = True

            # If attribute does not match the filter, drop it
            if drop:
                continue

            if self.honour_ids_flag:
                to_ids = a.get('to_ids', False)
                if not to_ids:
                    continue

            indicator = a.get('value', None)
            if indicator is None:
                LOG.error('{} - attribute with no value: {!r}'.format(self.name, a))
                continue

            iv = {}

            # Populate iv with the attributes from the event.
            for aname, aexpr in self.attribute_attributes.iteritems():
                try:
                    eresult = aexpr.search(a)
                except:
                    continue

                if eresult is None:
                    continue

                iv['{}_attribute_{}'.format(self.prefix, aname)] = eresult

            iv.update(base_value)

            # Convert MISP type to minemeld type
            itype = a.get('type', None)
            if itype == 'ip-src':
                iv['type'] = self._detect_ip_version(indicator)
                iv['direction'] = 'inbound'
            elif itype == 'ip-src|port':
                iv['type'] = self._detect_ip_version(indicator.split('|')[0]) + '.port'
                iv['direction'] = 'inbound'
            elif itype == 'ip-dst':
                iv['type'] = self._detect_ip_version(indicator)
                iv['direction'] = 'outbound'
            elif itype == 'ip-dst|port':
                iv['type'] = self._detect_ip_version(indicator.split('|')[0]) + '.port'
                iv['direction'] = 'outbound'
            elif itype == 'domain|ip':
                iv['type'] = 'domain.' + self._detect_ip_version(indicator.split('|')[1])
            else:
                iv['type'] = _MISP_TO_MINEMELD.get(itype, None)

            if iv['type'] is None:
                LOG.error('{} - Unhandled indicator type: {!r}'.format(self.name, a))
                continue

            result.append([indicator, iv])

            LOG.info('Added')

            if self.indicator_types is not None:
                result = [[ti, tiv] for ti, tiv in result if tiv['type'] in self.indicator_types]

        return result

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()
        super(Miner, self).hup(source)

    @staticmethod
    def gc(name, config=None):
        BasePollerFT.gc(name, config=config)

        side_config_path = None
        if config is not None:
            side_config_path = config.get('side_config', None)
        if side_config_path is None:
            side_config_path = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '{}_side_config.yml'.format(name)
            )

        try:
            os.remove(side_config_path)
        except:
            pass

        client_cert_required = False
        if config is not None:
            client_cert_required = config.get('client_cert_required', False)

        if client_cert_required:
            cert_path = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '{}.crt'.format(name)
            )

            try:
                os.remove(cert_path)
            except:
                pass

            key_path = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '{}.pem'.format(name)
            )

            try:
                os.remove(key_path)
            except:
                pass
