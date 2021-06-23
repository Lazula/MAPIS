#!/usr/bin/python3
#
# SPDX-FileCopyrightText: Copyright (C) 2020-2021 Lazula <26179473+Lazula@users.noreply.github.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# MAPIS: Multi-API Search - Identify malicious hosts and hashes
# Copyright (C) 2020-2021 Lazula <26179473+Lazula@users.noreply.github.com>
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

import colorama

SUCCESS_STYLE = f"{colorama.Fore.GREEN}{colorama.Style.BRIGHT}"
FAIL_STYLE = f"{colorama.Fore.LIGHTRED_EX}{colorama.Style.BRIGHT}"

def print_status(success, api, target, status_code=None):
    output = "".join([
        f"{SUCCESS_STYLE}Successful " if success else f"{FAIL_STYLE}Failed ",
        f"{api} request for {target}",
        f"with error code {status_code}" if status_code else ""
    ])


def add_ip_api_data(target_api_data, response, target):
    if response.status_code == 200:
        print_status(True, "ip-api", target)
        target_api_data["ip_api"] = response.json()
    else:
        print_status(False, "ip-api", target, response.status_code)


def add_shodan_data(target_api_data, response, target):
    if response.status_code == 200:
        print_status(True, "shodan", target)
        target_api_data["shodan"] = response.json()
    else:
        print_status(False, "shodan", target, response.status_code)


def add_virustotal_data(target_api_data, response, target):
    if response == "NotFoundError":
        print_status(False, "shodan", target, '"Not Found"')
    elif response == "APIError":
        print_status(False, "shodan", target, '"API Error"')
    else:
        print_status(True, "virustotal", target)
        target_api_data["virustotal"] = response


def add_threatcrowd_data(target_api_data, response, target):
    if response.status_code == 200:
        print_status(True, "threatcrowd", target)
        target_api_data["threatcrowd"] = response.json()
    else:
        print_status(False, "threatcrowd", target, response.status_code)


def add_alienvault_otx_data_ip(target_api_data, responses, target):
    url_response, malware_response = responses

    url_data = url_response.json() if url_response.status_code == 200 else None
    malware_data = malware_response.json() if malware_response.status_code == 200 else None

    if url_data:
        print_status(True, "alienvault otx url", target)
        target_api_data["alienvault_otx"]["url"] = url_data
    else:
        print_status(False, "alienvault otx url", target, url_response.status_code)

    if malware_data:
        print_status(True, "alienvault otx malware", target)
        target_api_data["alienvault_otx"]["malware"] = malware_data
    else:
        print_status(False, "alienvault otx malware", target, malware_response.status_code)


def add_alienvault_otx_data_hash(target_api_data, responses, target):
    general_response, analysis_response = responses

    general_data = general_response.json() if general_response.status_code == 200 else None
    analysis_data = analysis_response.json() if analysis_response.status_code == 200 else None

    if general_data:
        print_status(True, "alienvault otx general", target)
        target_api_data["alienvault_otx"]["general"] = general_data
    else:
        print_status(False, "alienvault otx general", target, general_response.status_code)

    if analysis_data:
        print_status(True, "alienvault otx analysis", target)
        target_api_data["alienvault_otx"]["analysis"] = analysis_data
    else:
        print_status(False, "alienvault otx analysis", target, analysis_response.status_code)


def add_alienvault_otx_data(target_api_data, responses, target, target_type):
    target_api_data["alienvault_otx"] = dict()

    if target_type == "address":
        add_alienvault_otx_data_ip(target_api_data, responses, target)
    elif target_type == "hash":
        add_alienvault_otx_data_hash(target_api_data, responses, target)
    else:
        raise ValueError(f"Unsupported target type {target_type}")
