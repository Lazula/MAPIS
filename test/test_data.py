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

import json
import unittest

from mapis_data import *
from mapis_requests import dummy_response

class TestPrintStatus(unittest.TestCase):
    api = "test_api"
    target: Target = Target("target_name", TargetType.Address)

    def test_constants(self):
        self.assertEqual(
            Style.SUCCESS,
            colorama.Style.BRIGHT + colorama.Fore.GREEN
        )
        self.assertEqual(
            Style.FAIL,
            colorama.Style.BRIGHT + colorama.Fore.LIGHTRED_EX
        )

        self.assertEqual(
            Strings.SUCCESS,
            Style.SUCCESS + "Successful {api} request for {target}"
        )
        self.assertEqual(
            Strings.FAIL,
            Style.FAIL + "Failed {api} request for {target}"
        )
        self.assertEqual(
            Strings.FAIL_WITH_CODE,
            Style.FAIL + "Failed {api} request for {target} with error code {status_code}"
        )


    def test_status_string_success(self):
        self.assertEqual(
            status_string(True, self.api, self.target),
            Strings.SUCCESS.format(api=self.api, target=self.target)
        )


    def test_status_string_failure(self):
        self.assertEqual(
            status_string(False, self.api, self.target),
            Strings.FAIL.format(api=self.api, target=self.target)
        )
        self.assertEqual(
            status_string(False, self.api, self.target, status_code=400),
            Strings.FAIL_WITH_CODE.format(api=self.api, target=self.target, status_code=400)
        )


class TestAddAPIData(unittest.TestCase):
    target: Target = Target("127.0.0.1", TargetType.Address)
    target_hash: Target = Target("00000000000000000000000000000000", TargetType.Hash)

    def test_add_ip_api_data(self):
        target_api_data = dict()
        ip_api_data = {"key": "value"}
        response = dummy_response(json.dumps(ip_api_data).encode())
        add_ip_api_data(target_api_data, response, self.target)
        self.assertEqual(target_api_data["ip_api"], ip_api_data)

        target_api_data = dict()
        ip_api_data = {"key": "value"}
        response = dummy_response(json.dumps(ip_api_data).encode())
        response.status_code = 400
        add_ip_api_data(target_api_data, response, self.target)
        self.assertFalse("ip_api" in target_api_data)


    def test_add_shodan_data(self):
        target_api_data = dict()
        shodan_data = {"key": "value"}
        response = dummy_response(json.dumps(shodan_data).encode())
        add_shodan_data(target_api_data, response, self.target)
        self.assertEqual(target_api_data["shodan"], shodan_data)

        target_api_data = dict()
        shodan_data = {"key": "value"}
        response = dummy_response(json.dumps(shodan_data).encode())
        response.status_code = 400
        add_shodan_data(target_api_data, response, self.target)
        self.assertFalse("shodan" in target_api_data)


    def test_add_virustotal_data(self):
        target_api_data = dict()
        virustotal_data = { "timeout":0, "undetected":0, "harmless":0, "suspicious":0, "malicious":0 }
        response = virustotal_data
        add_virustotal_data(target_api_data, response, self.target)
        self.assertEqual(target_api_data["vt"], virustotal_data)

        target_api_data = dict()

        response = "NotFoundError"
        add_virustotal_data(target_api_data, response, self.target)
        self.assertFalse("vt" in target_api_data)

        response = "APIError"
        add_virustotal_data(target_api_data, response, self.target)
        self.assertFalse("vt" in target_api_data)


    def test_add_threatcrowd_data(self):
        target_api_data = dict()
        threatcrowd_data = {"key": "value"}
        response = dummy_response(json.dumps(threatcrowd_data).encode())
        add_threatcrowd_data(target_api_data, response, self.target)
        self.assertEqual(target_api_data["tc"], threatcrowd_data)

        target_api_data = dict()
        threatcrowd_data = {"key": "value"}
        response = dummy_response(json.dumps(threatcrowd_data).encode())
        response.status_code = 400
        add_threatcrowd_data(target_api_data, response, self.target)
        self.assertFalse("tc" in target_api_data)


    def test_add_alienvault_otx_data_address(self):
        target_api_data = dict()
        url_data = {"key1": "value1"}
        malware_data = {"key2": "value2"}
        url_response = dummy_response(json.dumps(url_data).encode())
        malware_response = dummy_response(json.dumps(malware_data).encode())
        responses = (url_response, malware_response)
        add_alienvault_otx_data(target_api_data, responses, self.target)
        expected_otx_data = {
            "url": url_data,
            "malware": malware_data
        }
        self.assertEqual(target_api_data["otx"], expected_otx_data)

        target_api_data = dict()
        url_data = {"key1": "value1"}
        malware_data = {"key2": "value2"}
        url_response = dummy_response(json.dumps(url_data).encode())
        url_response.status_code = 400
        malware_response = dummy_response(json.dumps(malware_data).encode())
        responses = (url_response, malware_response)
        add_alienvault_otx_data(target_api_data, responses, self.target)
        expected_otx_data = {
            "malware": malware_data
        }
        self.assertEqual(target_api_data["otx"], expected_otx_data)

        target_api_data = dict()
        url_data = {"key1": "value1"}
        malware_data = {"key2": "value2"}
        url_response = dummy_response(json.dumps(url_data).encode())
        malware_response = dummy_response(json.dumps(malware_data).encode())
        malware_response.status_code = 400
        responses = (url_response, malware_response)
        add_alienvault_otx_data(target_api_data, responses, self.target)
        expected_otx_data = {
            "url": url_data
        }
        self.assertEqual(target_api_data["otx"], expected_otx_data)

        target_api_data = dict()
        url_data = {"key1": "value1"}
        malware_data = {"key2": "value2"}
        url_response = dummy_response(json.dumps(url_data).encode())
        url_response.status_code = 400
        malware_response = dummy_response(json.dumps(malware_data).encode())
        malware_response.status_code = 400
        responses = (url_response, malware_response)
        add_alienvault_otx_data(target_api_data, responses, self.target)
        self.assertFalse("otx" in target_api_data)


    def test_add_alienvault_otx_api_data_hash(self):
        target_api_data = dict()
        general_data = {"key1": "value2"}
        analysis_data = {"key2": "value2"}
        general_response = dummy_response(json.dumps(general_data).encode())
        analysis_response = dummy_response(json.dumps(analysis_data).encode())
        responses = (general_response, analysis_response)
        add_alienvault_otx_data(target_api_data, responses, self.target_hash)
        expected_otx_data = {
            "general": general_data,
            "analysis": analysis_data
        }
        self.assertEqual(target_api_data["otx"], expected_otx_data)

        target_api_data = dict()
        general_data = {"key1": "value1"}
        analysis_data = {"key2": "value2"}
        general_response = dummy_response(json.dumps(general_data).encode())
        general_response.status_code = 400
        analysis_response = dummy_response(json.dumps(analysis_data).encode())
        responses = (general_response, analysis_response)
        add_alienvault_otx_data(target_api_data, responses, self.target_hash)
        expected_otx_data = {
            "analysis": analysis_data
        }
        self.assertEqual(target_api_data["otx"], expected_otx_data)

        target_api_data = dict()
        general_data = {"key1": "value1"}
        analysis_data = {"key2": "value2"}
        general_response = dummy_response(json.dumps(general_data).encode())
        analysis_response = dummy_response(json.dumps(analysis_data).encode())
        analysis_response.status_code = 400
        responses = (general_response, analysis_response)
        add_alienvault_otx_data(target_api_data, responses, self.target_hash)
        expected_otx_data = {
            "general": general_data
        }
        self.assertEqual(target_api_data["otx"], expected_otx_data)

        target_api_data = dict()
        general_data = {"key1": "value1"}
        analysis_data = {"key2": "value2"}
        general_response = dummy_response(json.dumps(general_data).encode())
        general_response.status_code = 400
        analysis_response = dummy_response(json.dumps(analysis_data).encode())
        analysis_response.status_code = 400
        responses = (general_response, analysis_response)
        add_alienvault_otx_data(target_api_data, responses, self.target_hash)
        self.assertFalse("otx" in target_api_data)


    def test_add_api_data_address(self):
        target_api_data = dict()

        ip_api_data = {"key": "value"}
        ip_api_response = dummy_response(json.dumps(ip_api_data).encode())
        add_api_data(API.IPAPI, target_api_data, ip_api_response, self.target)

        shodan_data = {"key": "value"}
        shodan_response = dummy_response(json.dumps(shodan_data).encode())
        add_api_data(API.Shodan, target_api_data, shodan_response, self.target)

        virustotal_data = { "timeout":0, "undetected":0, "harmless":0, "suspicious":0, "malicious":0 }
        virustotal_response = virustotal_data
        add_api_data(API.VirusTotal, target_api_data, virustotal_response, self.target)

        threatcrowd_data = {"key": "value"}
        threatcrowd_response = dummy_response(json.dumps(threatcrowd_data).encode())
        add_api_data(API.ThreatCrowd, target_api_data, threatcrowd_response, self.target)

        url_data = {"key1": "value1"}
        malware_data = {"key2": "value2"}
        url_response = dummy_response(json.dumps(url_data).encode())
        malware_response = dummy_response(json.dumps(malware_data).encode())
        alienvault_otx_responses = (url_response, malware_response)
        add_api_data(API.AlienVault, target_api_data, alienvault_otx_responses, self.target)

        expected_api_data = {
            "ip_api": ip_api_data,
            "shodan": shodan_data,
            "vt": virustotal_data,
            "tc": threatcrowd_data,
            "otx": {
                "url": url_data,
                "malware": malware_data
            }
        }
        self.assertEqual(target_api_data, expected_api_data)


    def test_add_api_data_hash(self):
        target_api_data = dict()

        virustotal_data = { "timeout":0, "undetected":0, "harmless":0, "suspicious":0, "malicious":0 }
        virustotal_response = virustotal_data
        add_api_data(API.VirusTotal, target_api_data, virustotal_response, self.target_hash)

        threatcrowd_data = {"key": "value"}
        threatcrowd_response = dummy_response(json.dumps(threatcrowd_data).encode())
        add_api_data(API.ThreatCrowd, target_api_data, threatcrowd_response, self.target_hash)

        general_data = {"key1": "value1"}
        analysis_data = {"key2": "value2"}
        general_response = dummy_response(json.dumps(general_data).encode())
        analysis_response = dummy_response(json.dumps(analysis_data).encode())
        alienvault_otx_responses = (general_response, analysis_response)
        add_api_data(API.AlienVault, target_api_data, alienvault_otx_responses, self.target_hash)

        expected_api_data = {
            "vt": virustotal_data,
            "tc": threatcrowd_data,
            "otx": {
                "general": general_data,
                "analysis": analysis_data
            }
        }
        self.assertEqual(target_api_data, expected_api_data)
