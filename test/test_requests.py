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

import unittest

from mapis_requests import *

class TestDummyResponse(unittest.TestCase):
    def test_dummy_response(self):
        resp = dummy_response(b'{"key": "value"}')
        self.assertIsInstance(resp, requests.models.Response)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.text, '{"key": "value"}')
        self.assertEqual(resp.json(), {"key": "value"})


class TestMakeRequestAddress(unittest.TestCase):
    def test_make_request_address(self):
        raise NotImplementedError


class TestMakeRequestHash(unittest.TestCase):
    def test_make_request_hash(self):
        raise NotImplementedError


class TestRequestIPAPI(unittest.TestCase):
    def test_request_ip_api(self):
        raise NotImplementedError


class TestRequestShodan(unittest.TestCase):
    def test_request_shodan(self):
        raise NotImplementedError


class TestRequestVirusTotal(unittest.TestCase):
    def test_request_virustotal_address(self):
        raise NotImplementedError


    def test_request_virustotal_hash(self):
        raise NotImplementedError


class TestRequestThreatCrowd(unittest.TestCase):
    def test_request_threatcrowd_address(self):
        raise NotImplementedError


    def test_request_threatcrowd_hash(self):
        raise NotImplementedError


class TestRequestAlienVaultOTX(unittest.TestCase):
    def test_request_alienvault_otx_address(self):
        raise NotImplementedError


    def test_request_alienvault_otx_hash(self):
        raise NotImplementedError


