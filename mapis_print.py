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

import colorama
import itertools

from copy import deepcopy
from dataclasses import dataclass

from mapis_types import *

STORED_FORE: colorama.ansi.AnsiFore = deepcopy(colorama.Fore)

def disable_color() -> None:
    """This is VERY hacky and probably a terrible idea but it works.
It hijacks ALL color, for the entire program since it directly modifies the
colorama properties."""
    for color_name in vars(colorama.Fore):
        colorama.Fore.__dict__[color_name] = ""


def enable_color() -> None:
    colorama.Fore = STORED_FORE


@dataclass
class PrintStyle:
    key_style: str = colorama.Style.NORMAL
    key_color: str = colorama.Fore.RESET
    value_style: str = colorama.Style.NORMAL
    value_color: str = colorama.Fore.RESET


# TODO: should be a method on PrintStyle
def format_dict_output(key, value, print_style: PrintStyle = None) -> str:
    if print_style is None:
        print_style = PrintStyle()

    return "".join([
        print_style.key_style,
        print_style.key_color,
        str(key),
        colorama.Style.NORMAL + colorama.Fore.RESET,
        ": ",
        print_style.value_style,
        print_style.value_color,
        str(value),
    ])


IP_API_PARAMS = { "ISP": "isp", "ASN": "as", "Country Code": "countryCode",
                "Country": "country", "Region Code": "region",
                "Region": "regionName", "Zip Code": "zip",
                "Time Zone": "timezone", "Latitude": "lat",
                "Longitude": "lon" }


class IPAPIStyle:
    ANNOUNCE = colorama.Style.BRIGHT

    ENTRY = PrintStyle(
        key_style=colorama.Style.BRIGHT,
        key_color=colorama.Fore.WHITE,
        value_color=colorama.Fore.WHITE
    )


class IPAPIStrings:
    ANNOUNCE = IPAPIStyle.ANNOUNCE + "ip-api.com API Response:"


def print_ip_api(api_data: dict) -> None:
    print(IPAPIStrings.ANNOUNCE)

    for name, key in IP_API_PARAMS.items():
        print(format_dict_output(name, api_data[key], IPAPIStyle.ENTRY))
    print()


SHODAN_PARAMS = { "Last Update": "last_update", "Open Ports": "ports",
                   "ISP": "isp", "Hostnames": "hostnames", "Country": "country",
                   "Latitude": "latitude", "Longitude": "longitude" }

class ShodanStyle:
    ANNOUNCE = colorama.Fore.MAGENTA + colorama.Style.BRIGHT
    NO_DATA = colorama.Fore.LIGHTRED_EX + colorama.Style.BRIGHT

    ENTRY = PrintStyle(
        key_style=colorama.Style.BRIGHT,
        key_color=colorama.Fore.MAGENTA,
        value_color=colorama.Fore.MAGENTA
    )


class ShodanStrings:
    ANNOUNCE = ShodanStyle.ANNOUNCE + "shodan.io API Response:"
    NO_DATA = ShodanStyle.NO_DATA + "No data found for {target}"


def print_shodan(api_data: dict, target: Target) -> None:
    print(ShodanStrings.ANNOUNCE)

    if "error" in api_data:
        print(ShodanStrings.NO_DATA.format(target=target))
        print()
        return


    for name, key in SHODAN_PARAMS.items():
        print(format_dict_output(name, api_data[key], ShodanStyle.ENTRY))
    print()


class VirusTotalStyle:
    ANNOUNCE = colorama.Fore.LIGHTCYAN_EX + colorama.Style.BRIGHT
    ERROR = colorama.Fore.LIGHTRED_EX + colorama.Style.BRIGHT
    PERMALINK = colorama.Fore.LIGHTCYAN_EX

    TIMEOUT = PrintStyle(
        key_style = colorama.Style.BRIGHT,
        key_color = colorama.Fore.WHITE)
    UNDETECTED = PrintStyle(
        key_style = colorama.Style.BRIGHT,
        key_color = colorama.Fore.WHITE)
    HARMLESS = PrintStyle(
        key_style = colorama.Style.BRIGHT,
        key_color = colorama.Fore.GREEN)
    SUSPICIOUS = PrintStyle(
        key_style = colorama.Style.BRIGHT,
        key_color = colorama.Fore.YELLOW)
    MALICIOUS = PrintStyle(
        key_style = colorama.Style.BRIGHT,
        key_color = colorama.Fore.LIGHTRED_EX)


class VirusTotalStrings:
    ANNOUNCE = VirusTotalStyle.ANNOUNCE + "VirusTotal API Response:"
    ERROR = VirusTotalStyle.ERROR + "Error: {error}"
    PERMALINK_ADDRESS = VirusTotalStyle.PERMALINK + "https://www.virustotal.com/gui/ip-address/{target}/detection"
    PERMALINK_HASH = VirusTotalStyle.PERMALINK + "https://www.virustotal.com/gui/file/{target}/detection"


VIRUSTOTAL_PARAMS = (
    ("timeout", "Timed Out", VirusTotalStyle.TIMEOUT),
    ("undetected", "Undetected", VirusTotalStyle.UNDETECTED),
    ("harmless", "Harmless", VirusTotalStyle.HARMLESS),
    ("suspicious", "Suspicious", VirusTotalStyle.SUSPICIOUS),
    ("malicious", "Malicious", VirusTotalStyle.MALICIOUS)
)


def print_virustotal(api_data: dict, target: Target) -> None:
    print(VirusTotalStrings.ANNOUNCE)

    error = api_data.get("error")
    if error is not None:
        error = {
            "NotFoundError": "Not Found",
            "APIError": "API Error"
        }[error]
        print(VirusTotalStrings.ERROR.format(error=error))
        return

    for key, name, style in VIRUSTOTAL_PARAMS:
        print(format_dict_output(name, api_data[key], style))

    if target.type == TargetType.Address:
        print(VirusTotalStrings.PERMALINK_ADDRESS.format(target=target))
    elif target.type == TargetType.Hash:
        print(VirusTotalStrings.PERMALINK_HASH.format(target=target))
    print()


class ThreatCrowdStyle:
    ANNOUNCE = colorama.Fore.YELLOW + colorama.Style.BRIGHT
    NO_RESPONSE = colorama.Fore.RED + colorama.Style.BRIGHT

    class MaliciousVote:
        MAYBE = colorama.Style.BRIGHT
        YES = colorama.Style.BRIGHT + colorama.Fore.RED
        NO = colorama.Style.BRIGHT + colorama.Fore.GREEN
        UNAVAILABLE = colorama.Style.BRIGHT + colorama.Fore.LIGHTRED_EX

    SECTION_ANNOUNCE = colorama.Fore.WHITE + colorama.Style.DIM
    SECTION_EMPTY = colorama.Fore.LIGHTRED_EX + colorama.Style.BRIGHT

    ALIAS_ENTRY = PrintStyle(key_style=colorama.Style.BRIGHT, key_color=colorama.Fore.WHITE)

    PERMALINK = colorama.Fore.YELLOW


class ThreatCrowdStrings:
    ANNOUNCE = ThreatCrowdStyle.ANNOUNCE + "ThreatCrowd API Response:"
    NO_RESPONSE = ThreatCrowdStyle.NO_RESPONSE + "No results found for {target}"

    class MaliciousVote:
        MAYBE = ThreatCrowdStyle.MaliciousVote.MAYBE + "{target} has even or no maliciousness votes"
        YES = ThreatCrowdStyle.MaliciousVote.YES + "{target} has been voted malicious"
        NO = ThreatCrowdStyle.MaliciousVote.NO = "{target} has been voted not malicious"
        UNAVAILABLE = ThreatCrowdStyle.MaliciousVote.UNAVAILABLE + """Could not process vote data "{given}" (expected "-1", "0", or "1")"""

    DOMAIN_ANNOUNCE = ThreatCrowdStyle.SECTION_ANNOUNCE + "Domains linked with {target} (first 25):"
    ADDRESS_DOMAIN_ENTRY = "{domain} (resolved {last_resolved})"
    DOMAIN_EMPTY = ThreatCrowdStyle.SECTION_EMPTY + "No domains found"

    HASH_ANNOUNCE = ThreatCrowdStyle.SECTION_ANNOUNCE + "Hashes linked with {target} (first 25):"
    HASH_EMPTY = ThreatCrowdStyle.SECTION_EMPTY + "No hashes found"
    #PERMALINK_ADDRESS = ThreatCrowdStyle.PERMALINK + "http://ci-www.threatcrowd.org/ip.php?ip={target}"

    ALIAS_ANNOUNCE = ThreatCrowdStyle.SECTION_ANNOUNCE + "Alias hashes for {target}:"
    SCAN_ANNOUNCE = ThreatCrowdStyle.SECTION_ANNOUNCE + "Scan results for {target} (first 25):"
    SCAN_EMPTY = ThreatCrowdStyle.SECTION_EMPTY + "No scan results"
    ADDRESSES_ANNOUNCE = ThreatCrowdStyle.SECTION_ANNOUNCE + "IP addresses linked with {target} (first 25):"
    ADDRESSES_EMPTY = ThreatCrowdStyle.SECTION_EMPTY + "No related IP addresses"
    REFERENCE_ANNOUNCE = ThreatCrowdStyle.SECTION_ANNOUNCE + "References for {target} (first 25):"
    REFERENCE_EMPTY = ThreatCrowdStyle.SECTION_EMPTY + "No references found"
    #PERMALINK_HASH = ThreatCrowdStyle.PERMALINK + "http://ci-www.threatcrowd.org/malware.php?md5={target}"


def print_threatcrowd_address(target_api_data: dict, target: Target) -> None:
    # TODO: option to show more than 25
    resolutions = target_api_data["resolutions"]
    if len(resolutions) > 0:
        print(ThreatCrowdStrings.DOMAIN_ANNOUNCE.format(target=target))
        print(", ".join((
            ThreatCrowdStrings.ADDRESS_DOMAIN_ENTRY.format(**resolution)
            for resolution in resolutions[:25]
        )))
    else:
        print(ThreatCrowdStrings.DOMAIN_EMPTY)
    print()

    hashes = target_api_data["hashes"]
    if len(hashes) > 0:
        print(ThreatCrowdStrings.HASH_ANNOUNCE.format(target=target))
        print(", ".join(hashes[:25]))
    else:
        print(ThreatCrowdStrings.HASH_EMPTY)
    print()


def print_threatcrowd_hash(target_api_data: dict, target: Target) -> None:
    print(ThreatCrowdStrings.ALIAS_ANNOUNCE.format(target=target))
    print(format_dict_output("MD5", target_api_data["md5"], ThreatCrowdStyle.ALIAS_ENTRY))
    print(format_dict_output("SHA1", target_api_data["sha1"], ThreatCrowdStyle.ALIAS_ENTRY))
    print()

    scans = target_api_data["scans"][:25]
    if len(scans) > 0:
        print(ThreatCrowdStrings.SCAN_ANNOUNCE.format(target=target))
        print(", ".join(scans))
    else:
        print(ThreatCrowdStrings.SCAN_EMPTY)
    print()

    domains = target_api_data["domains"][:25]
    if len(domains) > 0:
        print(ThreatCrowdStrings.DOMAIN_ANNOUNCE.format(target=target))
        print(", ".join(domains))
    else:
        print(ThreatCrowdStrings.DOMAIN_EMPTY)
    print()

    addresses = target_api_data["ips"][:25]
    if len(addresses) > 0:
        print(ThreatCrowdStrings.ADDRESSES_ANNOUNCE.format(target=target))
        print(", ".join(addresses))
    else:
        print(ThreatCrowdStrings.ADDRESSES_EMPTY)
    print()

    references = target_api_data["references"][:25]
    if len(references) > 0:
        print(ThreatCrowdStrings.REFERENCE_ANNOUNCE.format(target=target))
        print(", ".join(references))
    else:
        print(ThreatCrowdStrings.REFERENCE_EMPTY)
    print()


def print_threatcrowd(target_api_data: dict, target: Target) -> None:
    print(ThreatCrowdStrings.ANNOUNCE)

    if target_api_data["response_code"] == "0":
        print(ThreatCrowdStrings.NO_RESPONSE.format(target=target))
        print()
        return

    try:
        if target_api_data["votes"] == "0":
            print(ThreatCrowdStrings.MaliciousVote.MAYBE.format(target=target))
        elif target_api_data["votes"] == "-1":
            print(ThreatCrowdStrings.MaliciousVote.YES.format(target=target))
        elif target_api_data["votes"] == "1":
            print(ThreatCrowdStrings.MaliciousVote.NO.format(target=target))
        else:
            print(ThreatCrowdStrings.MaliciousVote.UNAVAILABLE.format(given=target_api_data["votes"]))
        print()
    except KeyError:
        pass # TODO show not found

    if target.type == TargetType.Address:
        print_threatcrowd_address(target_api_data, target)
    elif target.type == TargetType.Hash:
        print_threatcrowd_hash(target_api_data, target)

    try:
        print(ThreatCrowdStyle.PERMALINK + target_api_data["permalink"])
    except KeyError:
        pass

    print()


class AlienVaultOTXStyle:
    ANNOUNCE = colorama.Fore.LIGHTBLACK_EX + colorama.Style.BRIGHT
    SECTION_ANNOUNCE = colorama.Fore.LIGHTBLACK_EX
    SECTION_EMPTY = colorama.Fore.LIGHTRED_EX

    GENERAL_ENTRY = PrintStyle(key_style=colorama.Style.BRIGHT)
    ANALYSIS_ENTRY = PrintStyle(key_style=colorama.Style.BRIGHT)

    PERMALINK = colorama.Fore.LIGHTBLACK_EX + colorama.Style.BRIGHT


class AlienVaultOTXStrings:
    ANNOUNCE = AlienVaultOTXStyle.ANNOUNCE + "AlienVault OTX API Response:"

    DOMAIN_ANNOUNCE = AlienVaultOTXStyle.SECTION_ANNOUNCE + "Domains linked to {target}:"
    DOMAIN_EMPTY = AlienVaultOTXStyle.SECTION_EMPTY + "No domains found for {target}"
    HASH_ANNOUNCE = AlienVaultOTXStyle.SECTION_ANNOUNCE + "Hashes linked to {target}:"
    HASH_EMPTY = AlienVaultOTXStyle.SECTION_EMPTY + "No hashes found for {target}"

    GENERAL_ANNOUNCE = AlienVaultOTXStyle.SECTION_ANNOUNCE + "General data for {target}:"
    GENERAL_EMPTY = AlienVaultOTXStyle.SECTION_EMPTY + "No general data for {target}"
    ANALYSIS_ANNOUNCE = AlienVaultOTXStyle.SECTION_ANNOUNCE + "Analysis data for {target}:"
    ANALYSIS_EMPTY = AlienVaultOTXStyle.SECTION_EMPTY + "No analysis data for {target}"

    PERMALINK_ADDRESS = AlienVaultOTXStyle.PERMALINK + "https://otx.alienvault.com/indicator/ip/{target}"
    PERMALINK_HASH = AlienVaultOTXStyle.PERMALINK + "https://otx.alienvault.com/indicator/file/{target}"


def print_alienvault_otx_address(target_url_api_data: dict, target_malware_api_data: dict, target: Target) -> None:
    # TODO: move data processing
    # Process url data
    unique_domains = list()
    for url_entry in target_url_api_data.get("url_list", list()):
        if url_entry["domain"] not in unique_domains and len(url_entry["domain"]) > 0:
            unique_domains.append(url_entry["domain"])

    if len(unique_domains) > 0:
        print(AlienVaultOTXStrings.DOMAIN_ANNOUNCE.format(target=target))
        print("\n".join(unique_domains))
    else:
        print(AlienVaultOTXStrings.DOMAIN_EMPTY.format(target=target))
    print()

    # Process malware data
    hashes = list()
    detections = list()
    for entry in target_malware_api_data.get("data", list()):
        if entry["hash"] not in hashes:
            hashes.append(entry["hash"])
            detections.append(entry["detections"])

    output_lines = list()
    for sample_hash, detections in zip(hashes, detections):
        output_line = sample_hash

        detection_output = ":"
        for name in detections.values():
            if name != "None" and name is not None:
                detection_output += f"{name},"
        if len(detection_output) > 1:
            output_line += detection_output[:-1]

        output_lines.append(output_line)

    if len(output_lines) > 0:
        print(AlienVaultOTXStrings.HASH_ANNOUNCE.format(target=target))
        print(*output_lines, sep="\n")
    else:
        print(AlienVaultOTXStrings.HASH_EMPTY.format(target=target))
    print()

    print(AlienVaultOTXStrings.PERMALINK_ADDRESS.format(target=target))
    print()


def print_alienvault_otx_hash(general_data: dict, analysis_data: dict, target: Target):
    # TODO: all of this data processing doesnt belong here
    pulse_data = general_data.get("pulse_info", dict())
    pulses = pulse_data.get("pulses", dict())

    names = [ pulse["name"] for pulse in pulses ]
    descriptions = [ pulse["description"] for pulse in pulses ]
    tags = list(itertools.chain.from_iterable((pulse["tags"] for pulse in pulses)))
    malware_families = list(itertools.chain.from_iterable((
        v["malware_families"] for v in pulse_data["related"].values()
    ))) if "related" in pulse_data else list()
    adversaries = list(itertools.chain.from_iterable((
        v["adversary"] for v in pulse_data["related"].values()
    ))) if "related" in pulse_data else list()

    general_output = {
        "Pulse count": pulse_data.get("count", "0"),
        "Pulse names": ", ".join(names) if names else "No names found",
        "Pulse tags": ", ".join(tags) if tags else "No tags found",
        "Pulse descriptions": ", ".join(( f'"{d}"' for d in descriptions)) if descriptions else "No descriptions available",
        "Malware families": ", ".join(malware_families) if malware_families else "No malware families identified",
        "Adversaries": ", ".join(adversaries) if adversaries else "No adversaries identified"
    }

    if analysis_data.get("analysis"):
        analysis_info = analysis_data["analysis"]["info"]["results"]
        analysis_plugins = analysis_data["analysis"]["plugins"]
        analysis_pe32info = analysis_plugins["pe32info"]["results"]
        analysis_yarad = analysis_plugins["yarad"]["results"]
        analysis_peanomal = analysis_plugins["peanomal"]["results"]

        packers = analysis_pe32info.get("packers")
        yara_rule_names = [ x["rule_name"] for x in analysis_yarad["detection"] ]

    # TODO: check fragility
    try:
        analysis_output = {
            "File class": analysis_info["file_class"],
            "File type": analysis_info["file_type"],
            "File size": f'{analysis_info["filesize"]} bytes', # TODO: human readable
            "MD5 hash": analysis_info["md5"],
            "SHA1 hash": analysis_info["sha1"],
            "SHA256 hash": analysis_info["sha256"],
            "SSDeep hash": analysis_info["ssdeep"],
            "ImpHash": analysis_pe32info["imphash"],
            "PEHash": analysis_pe32info["pehash"],
            "Rich PEHash": analysis_pe32info.get("richhash", "No Rich PEHash"),
            "Anomalies detected by PEAnomal": analysis_peanomal["anomalies"],
            "Packers": ", ".join(packers) if packers else "No packers detected",
            "YARA compression rule detections": sum(1 for x in analysis_yarad["detection"]
                                                    if "category" in x and "compression" in x["category"]),
            "YARA code overlap rule detections": sum(1 for x in analysis_yarad["detection"]
                                                     if "category" in x and "CodeOverlap" in x["category"]),
            "YARA rule detection names": ", ".join(yara_rule_names) if yara_rule_names else "No YARA rules detected"
        }
    except NameError: # catch having no definitions from no analysis above
        analysis_output = None

    if general_output:
        print(AlienVaultOTXStrings.GENERAL_ANNOUNCE.format(target=target))
        print("\n".join((
            format_dict_output(key, value, AlienVaultOTXStyle.GENERAL_ENTRY)
            for key, value in general_output.items()
        )))
    else:
        print(AlienVaultOTXStrings.GENERAL_EMPTY.format(target=target))
    print()

    if analysis_output:
        print(AlienVaultOTXStrings.ANALYSIS_ANNOUNCE.format(target=target))
        print("\n".join((
            format_dict_output(key, value, AlienVaultOTXStyle.ANALYSIS_ENTRY)
            for key, value in analysis_output.items()
        )))
    else:
        print(AlienVaultOTXStrings.ANALYSIS_EMPTY.format(target=target))
    print()

    print(AlienVaultOTXStrings.PERMALINK_HASH.format(target=target))
    print()


def print_alienvault_otx(alienvault_otx_data: dict[str, dict], target: Target) -> None:
    print(AlienVaultOTXStrings.ANNOUNCE)

    if target.type == TargetType.Address:
        print_alienvault_otx_address(alienvault_otx_data["url"], alienvault_otx_data["malware"], target)
    elif target.type == TargetType.Hash:
        print_alienvault_otx_hash(alienvault_otx_data["general"], alienvault_otx_data["analysis"], target)


class PrintTargetStyle:
    DIVIDER = colorama.Style.BRIGHT
    ANNOUNCE = colorama.Style.BRIGHT
    EMPTY = colorama.Style.BRIGHT + colorama.Fore.LIGHTRED_EX
    FINISH = colorama.Style.BRIGHT


class PrintTargetStrings:
    DIVIDER = PrintTargetStyle.DIVIDER + "-"*20
    ANNOUNCE = "\n".join((
        DIVIDER,
        PrintTargetStyle.ANNOUNCE + "Report for {target}",
        DIVIDER
    ))
    EMPTY = "\n".join((
        DIVIDER,
        PrintTargetStyle.EMPTY + "No data available for {target}",
        DIVIDER
    ))
    FINISH = "\n".join((
        DIVIDER,
        PrintTargetStyle.FINISH + "End of report for {target}",
        DIVIDER
    ))


def print_target_data(target_data_dict: dict) -> None:
    target = target_data_dict["target"]
    target_api_data = target_data_dict["target_api_data"]

    print(PrintTargetStrings.ANNOUNCE.format(target=target))
    print()

    if not target_api_data:
        print(PrintTargetStrings.EMPTY.format(target=target))

    if "ip_api" in target_api_data:
        print_ip_api(target_api_data["ip_api"])

    if "shodan" in target_api_data:
        print_shodan(target_api_data["shodan"], target)

    if "vt" in target_api_data:
        print_virustotal(target_api_data["vt"], target)

    if "tc" in target_api_data:
        print_threatcrowd(target_api_data["tc"], target)

    if "otx" in target_api_data:
        print_alienvault_otx(target_api_data["otx"], target)

    print(PrintTargetStrings.FINISH.format(target=target))
    print()
