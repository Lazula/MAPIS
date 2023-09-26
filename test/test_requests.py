#!/usr/bin/python3
#
# SPDX-FileCopyrightText: Copyright (C) 2020-2023 Lazula <26179473+Lazula@users.noreply.github.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# MAPIS: Multi-API Search - Identify malicious hosts and hashes
# Copyright (C) 2020-2023 Lazula <26179473+Lazula@users.noreply.github.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import hashlib
import unittest

from argparse import Namespace
from requests.models import Response

from mapis_requests import *
from mapis import read_keys

google_dns_target = "8.8.8.8"

# Real threat samples
aridviper_address_target = "188.40.75.132"
aridviper_md5_hash_target = "003f0ed24b5f70ddc7c6e80f9c4dac73"
aridviper_sha1_hash_target = "75ec7d0d1b6b2b4c816cbc1b71cd0f8f06bd8c1b"


class TestDummyResponse(unittest.TestCase):
    def test_dummy_response(self):
        resp = dummy_response(b'{"key": "value"}')
        self.assertIsInstance(resp, requests.models.Response)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.text, '{"key": "value"}')
        self.assertEqual(resp.json(), {"key": "value"})


class TestMakeRequest(unittest.TestCase):
    def test_make_request_address(self):
        resp = make_request("ip_api", google_dns_target, "address", None)
        self.assertIsInstance(resp, Response)
        self.assertEqual(resp.status_code, 200)


    def test_make_request_hash(self):
        resp = make_request("otx", aridviper_md5_hash_target, "hash", None)
        self.assertIsInstance(resp[0], Response)
        self.assertIsInstance(resp[1], Response)
        self.assertEqual(resp[0].status_code, 200)
        self.assertEqual(resp[1].status_code, 200)


    def test_make_request_error(self):
        self.assertRaises(
            ValueError,
            make_request,
            "nonexistent_api", None, None, None
        )


class TestRequestIPAPI(unittest.TestCase):
    def test_request_ip_api(self):
        resp = request_ip_api(google_dns_target, "address")
        self.assertIsInstance(resp, Response)
        self.assertEqual(resp.status_code, 200)


class TestRequestShodan(unittest.TestCase):
    @classmethod
    def setUp(self):
        args = Namespace()
        args.keydir = "API_KEYS"
        args.api_list = ["shodan"]
        self.key = read_keys(args)["shodan"]


    def test_request_shodan_no_history_no_minify(self):
        resp = request_shodan(google_dns_target, "address", self.key, history=False, minify=False)
        self.assertIsInstance(resp, Response)
        self.assertEqual(resp.status_code, 200)


    def test_request_shodan_with_history_no_minify(self):
        resp = request_shodan(google_dns_target, "address", self.key, history=True, minify=False)
        self.assertIsInstance(resp, Response)
        self.assertEqual(resp.status_code, 200)


    def test_request_shodan_no_history_with_minify(self):
        resp = request_shodan(google_dns_target, "address", self.key, history=False, minify=True)
        self.assertIsInstance(resp, Response)
        self.assertEqual(resp.status_code, 200)


    def test_request_shodan_with_history_with_minify(self):
        resp = request_shodan(google_dns_target, "address", self.key, history=True, minify=True)
        self.assertIsInstance(resp, Response)
        self.assertEqual(resp.status_code, 200)


class TestRequestVirusTotal(unittest.TestCase):
    @classmethod
    def setUp(self):
        args = Namespace()
        args.keydir = "API_KEYS"
        args.api_list = ["vt"]
        self.client = vt.Client(read_keys(args)["vt"])


    @classmethod
    def tearDown(self):
        self.client.close()


    def test_request_virustotal_address(self):
        resp = request_virustotal(self.client, google_dns_target, "address")
        expected = {'harmless': 69, 'malicious': 2, 'suspicious': 0, 'undetected': 19, 'timeout': 0}
        self.assertEqual(resp, expected)


    def test_request_virustotal_hash(self):
        resp = request_virustotal(self.client, aridviper_md5_hash_target, "hash")
        expected = {'harmless': 0, 'type-unsupported': 4, 'suspicious': 0, 'confirmed-timeout': 0, 'timeout': 0, 'failure': 0, 'malicious': 55, 'undetected': 16}
        self.assertEqual(resp, expected)
        resp = request_virustotal(self.client, aridviper_sha1_hash_target, "hash")
        self.assertEqual(resp, expected)


class TestRequestThreatCrowd(unittest.TestCase):
    def test_request_threatcrowd_address(self):
        resp = request_threatcrowd(google_dns_target, "address")
        self.assertIsInstance(resp, Response)
        self.assertEqual(resp.status_code, 200)

        resp = request_threatcrowd(aridviper_address_target, "address")
        self.assertIsInstance(resp, Response)
        self.assertEqual(resp.status_code, 200)


    def test_request_threatcrowd_hash(self):
        resp_md5 = request_threatcrowd(aridviper_md5_hash_target, "hash")
        expected = {
            'response_code': '1',
            'md5': '003f0ed24b5f70ddc7c6e80f9c4dac73',
            'sha1':
            '75ec7d0d1b6b2b4c816cbc1b71cd0f8f06bd8c1b',
            'scans': [
                'TrojanAPT.Atravel.A4',
                'Trojan.Downloader.AridViper',
                'Trojan.FakeDir.VB',
                'Trojan'
            ],
            'ips': ['188.40.75.132'],
            'domains': [],
            'references': [],
            'permalink': 'https://www.threatcrowd.org/malware.php?md5=003f0ed24b5f70ddc7c6e80f9c4dac73'
        }
        self.assertEqual(resp_md5.json(), expected)

        resp_sha1 = request_threatcrowd(aridviper_sha1_hash_target, "hash")
        self.assertEqual({"response_code": "0"}, resp_sha1.json())


class TestRequestAlienVaultOTX(unittest.TestCase):
    def test_request_alienvault_otx_address(self):
        resp = request_alienvault_otx(google_dns_target, "address")
        self.assertIsInstance(resp[0], Response)
        self.assertIsInstance(resp[1], Response)
        self.assertEqual(resp[0].status_code, 200)
        self.assertEqual(resp[1].status_code, 200)


    def test_request_alienvault_otx_hash(self):
        resp = request_alienvault_otx(aridviper_md5_hash_target, "hash")
        self.assertIsInstance(resp[0], Response)
        self.assertIsInstance(resp[1], Response)
        self.assertEqual(resp[0].status_code, 200)
        self.assertEqual(resp[1].status_code, 200)
