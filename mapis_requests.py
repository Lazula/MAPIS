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

import requests
import vt


APIS = {
    "ip_api": {
        "name": "IP-API",
        "key_needed": False,
        "target_types": [ "address" ],
    },

    "shodan": {
        "name": "Shodan",
        "key_needed": True,
        "target_types": [ "address" ],
    },

    "vt": {
        "name": "VirusTotal",
        "key_needed": True,
        "target_types": [ "address", "hash" ],
    },

    "tc": {
        "name": "ThreatCrowd",
        "key_needed": False,
        "target_types": [ "address", "hash" ],
    },

    "otx": {
        "name": "AlienVault OTX",
        "key_needed": False,
        "target_types": [ "address", "hash" ],
    }
}

# APIS but only for those with key_needed
KEY_APIS = {
    api: data
        for api, data in APIS.items()
        if data["key_needed"]
}

def dummy_response(content):
    response = requests.models.Response()
    response.status_code = 200
    response._content = content
    return response

def make_request(api_name, target, target_type, keys, vt_client=None, dry_run=False):
    request_func_map = {
        "ip_api": request_ip_api,
        "shodan": request_shodan,
        "vt":     True, # Special case, see below
        "tc":     request_threatcrowd,
        "otx":    request_alienvault_otx,
    }

    try:
        request_func = request_func_map[api_name]
    except KeyError:
        raise ValueError(f"No such API {api_name}")

    if api_name == "vt":
        # Special case since key is used for client init
        return request_virustotal(vt_client, target, target_type, dry_run)
    elif api_name in KEY_APIS.keys():
        return request_func(target, target_type, keys[api_name], dry_run=dry_run)
    else:
        return request_func(target, target_type, dry_run=dry_run)


# Batch api supports up to 100 queries per request,
# but this would require some significant changes...
# maybe build a queue of IP addresses in the main loop?
# https://ip-api.com/docs/api:batch
def request_ip_api(target, target_type, dry_run=False):
    if target_type == "address":
        if dry_run:
            response = dummy_response(b'{"isp":"TEST_ISP", "org":"TEST_ORG", "as":12345,"countryCode":"CC", "country":"TEST_COUNTRY", "region":"TEST_REGION", "regionName":"TEST_REGION_NAME", "zip":12345, "timezone":"GMT", "lat":12, "lon":34}')
        else:
            response = requests.get(f"http://ip-api.com/json/{target}")
    else:
        raise ValueError(f"Target type {target_type} not supported.")

    return response


def request_shodan(target, target_type, key, history=False, minify=True, dry_run=False):
    if key is None and not dry_run:
        return None

    if target_type == "address":
        if dry_run:
            response = dummy_response(b'{"last_update":"2020-01-01T00:00:00.000000", "ports":[22,80,443], "isp":"TEST_ISP", "hostnames":"TEST_HOSTNAME", "country":"TEST_COUNTRY", "latitude":12, "longitude":34}')
        else:
            request_url = f"https://api.shodan.io/shodan/host/{target}?key={key}"
            if history:
                request_url += "&history"
            if minify:
                request_url += "&minify"
            response = requests.get(request_url)
    else:
        raise ValueError(f"Target type {target_type} not supported.")

    return response


def request_virustotal(client, target, target_type, dry_run=False):
    if client is None and not dry_run:
        return None

    if target_type == "address":
        if dry_run:
            response = { "timeout":0, "undetected":0, "harmless":0, "suspicious":0, "malicious":0 }
        else:
            try:
                url_id = vt.url_id(target)
                url_info = client.get_object("/urls/{}", url_id)
                response = url_info.last_analysis_stats
            except vt.APIError as e:
                if e.args[0] == "NotFoundError":
                    response = "NotFoundError"
                else:
                    response = "APIError"
    elif target_type == "hash":
        if dry_run:
            response = { "timeout":0, "undetected":0, "harmless":0, "suspicious":0, "malicious":0 }
        else:
            try:
                file_info = client.get_object("/files/{}", target)
                response = file_info.last_analysis_stats
            except vt.APIError as e:
                if e.args[0] == "NotFoundError":
                    response = "NotFoundError"
                else:
                    response = "APIError"
    else:
        raise ValueError(f"Target type {target_type} not supported.")

    return response


def request_threatcrowd(target, target_type, dry_run=False):
    if target_type == "address":
        if dry_run:
            response = dummy_response(b'{"response_code": "1", "votes": "0", "resolutions": [{"last_resolved": "2020-01-01", "domain": "example.com"}, {"last_resolved":"2020-01-01", "domain": "example.org"}], "hashes": ["00000000000000000000000000000000", "11111111111111111111111111111111", "22222222222222222222222222222222", "33333333333333333333333333333333"], "permalink":"http://ci-www.threatcrowd.org/ip.php?ip=127.0.0.1"}')
        else:
            response = requests.get(f"https://www.threatcrowd.org/searchApi/v2/ip/report/?ip={target}")
    elif target_type == "hash":
        if dry_run:
            response = dummy_response(b'{"response_code": "1", "votes": "0", "md5":"00000000000000000000000000000000", "sha1":"0000000000000000000000000000000000000000", "scans":["Trojan.Win32", "Trojan","Backdoor:Win32"], "ips":["10.0.0.1", "192.168.0.1", "172.16.0.1"], "domains":["example.com", "example.org"], "references": ["https://example.com", "https://example.org"], "permalink":"http://ci-www.threatcrowd.org/malware.php?md5=00000000000000000000000000000000"}')
        else:
            response = requests.get(f"https://www.threatcrowd.org/searchApi/v2/file/report/?resource={target}")
    else:
        raise ValueError(f"Target type {target_type} not supported.")

    return response


def request_alienvault_otx(target, target_type, dry_run=False):
    if target_type == "address":
        if dry_run:
            url_list_response = dummy_response(b'{"url_list":[{"domain":"example.com"}, {"domain":"example.org"}]}')
            malware_response  = dummy_response(b'{"count":2, "data":[{"detections":{"avast":"TEST_NAME_1", "avg":"None", "clamav":"TEST_NAME_2", "msdefender":"None"}, "hash":"0000000000000000000000000000000000000000000000000000000000000000"}, {"detections":{"avast":"None", "avg":"None", "clamav":"TEST_NAME_3", "msdefender":"None"}, "hash":"1111111111111111111111111111111111111111111111111111111111111111"}]}')
        else:
            url_list_response = requests.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{target}/url_list")
            malware_response  = requests.get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{target}/malware")
        responses = (url_list_response, malware_response)
    elif target_type == "hash":
        if dry_run:
            general_response = dummy_response(b'{"pulse_info": {"count": 2, "pulses": [{"name": "Example name 1", "description": "Example description 1", "tags": ["tag1", "tag2", "tag3"]}, {"name": "Example name 2", "description": "Example description 2", "tags": ["tag4", "tag5"]}], "related": {"other": {"adversary": ["adversary1", "adversary2", "adversary3"], "malware_families": ["malware_family1", "malware_family2", "malware_family3"]}}}}')
            analysis_response  = dummy_response(b'{"analysis": {"info": {"results": {"file_class": "PEXE", "file_type": "PE32 executable (GUI) Intel 80386, for MS Windows", "filesize": 1000000, "md5": "00000000000000000000000000000000", "sha1": "0000000000000000000000000000000000000000", "sha256": "0000000000000000000000000000000000000000000000000000000000000000", "ssdeep": "00000:11111111:2222222222:333333333333"}}, "plugins": {"pe32info": {"results": {"imphash": "00000000000000000000000000000000", "packers": null, "pehash": "0000000000000000000000000000000000000000", "richhash": "0000000000000000000000000000000000000000000000000000000000000000"}}, "peanomal": {"results": {"anomalies": 0, "detection": []}}, "yarad": {"results": {"detection": [{"category": ["compression"], "rule_name": "rule1", "severity": 0}, {"rule_name": "rule2", "severity": 0}, {"category": [], "rule_name": "rule3", "severity": 0}, {"category": [], "rule_name": "rule4", "severity": 0}]}}}}}')
        else:
            general_response  = requests.get(f"https://otx.alienvault.com/api/v1/indicators/file/{target}/general")
            analysis_response = requests.get(f"https://otx.alienvault.com/api/v1/indicators/file/{target}/analysis")
        responses = (general_response, analysis_response)
    else:
        raise ValueError(f"Target type {target_type} not supported.")

    return responses
