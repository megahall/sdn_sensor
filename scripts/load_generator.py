#!/usr/bin/env python

import base64
import collections
import copy
import csv
import hashlib
import hmac
import httplib
import ipdb
import itertools
import json
import logging
import os
import random
import re
import requests
import socket
import struct
import sys
import time
import urllib
import uuid

from pprint import pprint, pformat

from netaddr import *

log = logging.getLogger(__name__)
log.propagate = False
log.setLevel(logging.DEBUG)
formatter = logging.Formatter(fmt='%(asctime)s: load-generator.py: %(levelname)s: %(message)s')
handler   = logging.StreamHandler(stream=sys.stdout)
handler.setFormatter(formatter)
log.addHandler(handler)

script_directory = os.path.dirname(os.path.realpath(__file__))

rest_client   = requests.Session()
http_backend  = requests.adapters.HTTPAdapter(max_retries=1)
https_backend = requests.adapters.HTTPAdapter(max_retries=1)
rest_client.mount('http://', http_backend)
rest_client.mount('https://', https_backend)

FIELD_NAMES = ( 'id', 'type', 'threat_type', 'ip', 'dns', 'value' )

#  61084 ip
#   1939 url
#   1230 domain
IOC_TYPES = ( 'ip', 'url', 'domain' )

#  33841 brute_ip
#  16108 bot_ip
#   8534 tor_ip
#   1937 mal_url
#   1722 proxy_ip
#   1223 c2_domain
#    724 spam_ip
#    107 compromised_ip
#     47 mal_ip
#      7 dyn_dns
#      2 phish_url
THREAT_TYPES = {
    'ip':     ( 'brute_ip', 'bot_ip', 'tor_ip', 'proxy_ip', 'spam_ip', 'compromised_ip', 'mal_ip' ),
    'url':    ( 'mal_url', 'phish_url' ),
    'domain': ( 'c2_domain', 'dyn_dns' ),
}

matching_rows = []
filler_rows   = []
combined_logs = []

FILLER_WORDS  = []
FILLER_TLDS   = []

def json_dump(data, multiline=True):
    kwargs = { 'sort_keys': True }
    if multiline:
        kwargs['indent']     = 4
        kwargs['separators'] = (',', ': ')
    else:
        kwargs['separators'] = (', ', ': ')
    return json.dumps(data, **kwargs)

def chunked(items, n):
    for i in xrange(0, len(items), n):
        yield items[i:i + n]

def random_ip():
    return socket.inet_ntoa(struct.pack('>I', random.randint(0x00000001, 0xffffffff)))

def random_dns():
    return 'www.' + random.choice(FILLER_WORDS) + random.choice(FILLER_WORDS) + '.' + random.choice(FILLER_TLDS)

def get_url(dns):
    return 'http://' + dns + '/'

def load_matching_rows():
    with open(os.path.expanduser('~') + '/random.csv') as f:
        reader = csv.reader(f)
        for row_vector in reader:
            row = collections.OrderedDict(zip(FIELD_NAMES, row_vector))
            row['id'] = int(row['id'])
            matching_rows.append(row)

def load_filler_data():
    with open(os.path.expanduser('~') + '/random.txt') as f:
        FILLER_WORDS.extend([l.strip().lower() for l in f])
    with open(os.path.expanduser('~') + '/tlds.txt') as f:
        FILLER_TLDS.extend([l.strip().lower() for l in f if 'xn--' not in l])

def load_filler_rows():
    for i in xrange(0, len(matching_rows) * 100):
        id          = random.randrange(1, 200000000)
        ioc_type    = random.choice(IOC_TYPES)
        threat_type = random.choice(THREAT_TYPES[ioc_type])
        ip          = random_ip()
        dns         = random_dns() if ioc_type in ('domain', 'url') else ''
        value       = None
        if ioc_type == 'ip':     value = ip
        if ioc_type == 'domain': value = dns
        if ioc_type == 'url':    value = get_url(dns)
        row = collections.OrderedDict((
            ('id',          id),
            ('type',        ioc_type),
            ('threat_type', threat_type),
            ('ip',          ip),
            ('dns',         dns),
            ('value',       value),
        ))
        filler_rows.append(row)

def format_row(row):
    return 'id %09d type %s threat_type %s ip %s dns %s value %s' % \
        (row['id'], row['type'], row['threat_type'], row['ip'], row['dns'], row['value'])

def load_combined_logs():
    j = 0
    for i in xrange(0, len(filler_rows)):
        if i % 100 == 0:
            next_row = matching_rows[j]
            j += 1
        else:
            next_row = filler_rows[i]
        combined_logs.append(format_row(next_row))

SENSOR_IP      = '192.168.1.7'
SENSOR_PORT    = 514
SENSOR_ADDRESS = (SENSOR_IP, SENSOR_PORT)

def send_combined_logs():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.connect(SENSOR_ADDRESS)

    start   = time.time()
    counter = 0

    try:
        for message in itertools.cycle(combined_logs):
            udp_socket.send(message)
            counter += 1
    except KeyboardInterrupt as e:
        print 'stop sending logs'

    elapsed = time.time() - start
    rate    = float(counter) / elapsed
    print '%09d logs in %09.3d secs. or %010.3d logs / sec.' % (counter, elapsed, rate)

def main(argv=None):
    if argv is None:
        argv = sys.argv
    load_filler_data()
    load_matching_rows()
    load_filler_rows()
    load_combined_logs()
    send_combined_logs()

if __name__ == "__main__":
    sys.exit(main())
