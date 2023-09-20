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

from mapis_io import get_target_type

class Style:
    SUCCESS = colorama.Style.BRIGHT + colorama.Fore.GREEN
    FAIL = colorama.Style.BRIGHT + colorama.Fore.LIGHTRED_EX


class Strings:
    SUCCESS = Style.SUCCESS + "Successful {api} request for {target}"
    FAIL = Style.FAIL + "Failed {api} request for {target}"
    FAIL_WITH_CODE = Style.FAIL + "Failed {api} request for {target} with error code {status_code}"


def status_string(success: bool, api: str, target: str, status_code: int | str = None):
    kwargs = { "api": api, "target": target, "status_code": status_code }
    if success:
        return Strings.SUCCESS.format(**kwargs)
    else:
        if status_code is not None:
            return Strings.FAIL_WITH_CODE.format(**kwargs)
        else:
            return Strings.FAIL.format(**kwargs)


def add_api_data(api_name, target_api_data, response, target):
    data_func_map = {
        "ip_api": add_ip_api_data,
        "shodan": add_shodan_data,
        "vt":     add_virustotal_data,
        "tc":     add_threatcrowd_data,
        "otx":    add_alienvault_otx_data,
    }

    try:
        data_func = data_func_map[api_name]
    except KeyError:
        raise ValueError(f"No such API {api_name}")

    return data_func(target_api_data, response, target)


def add_ip_api_data(target_api_data, response, target):
    if response.status_code == 200:
        status_string(True, "ip-api", target)
        target_api_data["ip_api"] = response.json()
    else:
        status_string(False, "ip-api", target, response.status_code)


def add_shodan_data(target_api_data, response, target):
    if response.status_code == 200:
        status_string(True, "shodan", target)
        target_api_data["shodan"] = response.json()
    else:
        status_string(False, "shodan", target, response.status_code)


def add_virustotal_data(target_api_data, response, target):
    if response == "NotFoundError":
        status_string(False, "virustotal", target, '"Not Found"')
    elif response == "APIError":
        status_string(False, "virustotal", target, '"API Error"')
    else:
        status_string(True, "virustotal", target)
        target_api_data["vt"] = response


def add_threatcrowd_data(target_api_data, response, target):
    if response.status_code == 200:
        status_string(True, "threatcrowd", target)
        target_api_data["tc"] = response.json()
    else:
        status_string(False, "threatcrowd", target, response.status_code)


def add_alienvault_otx_data_ip(target_api_data, responses, target):
    url_response, malware_response = responses

    url_data = url_response.json() if url_response.status_code == 200 else None
    malware_data = malware_response.json() if malware_response.status_code == 200 else None

    if url_data or malware_data:
        target_api_data["otx"] = dict()

    if url_data:
        status_string(True, "alienvault otx url", target)
        target_api_data["otx"]["url"] = url_data
    else:
        status_string(False, "alienvault otx url", target, url_response.status_code)

    if malware_data:
        status_string(True, "alienvault otx malware", target)
        target_api_data["otx"]["malware"] = malware_data
    else:
        status_string(False, "alienvault otx malware", target, malware_response.status_code)


def add_alienvault_otx_data_hash(target_api_data, responses, target):
    general_response, analysis_response = responses

    general_data = general_response.json() if general_response.status_code == 200 else None
    analysis_data = analysis_response.json() if analysis_response.status_code == 200 else None

    if general_data or analysis_data:
        target_api_data["otx"] = dict()

    if general_data:
        status_string(True, "alienvault otx general", target)
        target_api_data["otx"]["general"] = general_data
    else:
        status_string(False, "alienvault otx general", target, general_response.status_code)

    if analysis_data:
        status_string(True, "alienvault otx analysis", target)
        target_api_data["otx"]["analysis"] = analysis_data
    else:
        status_string(False, "alienvault otx analysis", target, analysis_response.status_code)


def add_alienvault_otx_data(target_api_data, responses, target):
    # Since we know the target is already good, this recalculation is an
    # acceptable tradeoff for the simplicity of keeping parameters uniform
    target_type = get_target_type(target)

    if target_type == "address":
        add_alienvault_otx_data_ip(target_api_data, responses, target)
    elif target_type == "hash":
        add_alienvault_otx_data_hash(target_api_data, responses, target)
    else:
        raise ValueError(f"Unsupported target type {target_type}")
