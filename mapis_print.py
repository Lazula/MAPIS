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
import itertools

def disable_color():
    """This is VERY hacky and probably a terrible idea but it works.
It hijacks ALL color, for the entire program since it directly modifies the
colorama properties."""
    colorama.Fore.BLACK = ""
    colorama.Fore.BLUE = ""
    colorama.Fore.CYAN = ""
    colorama.Fore.GREEN = ""
    colorama.Fore.LIGHTBLACK_EX = ""
    colorama.Fore.LIGHTBLUE_EX = ""
    colorama.Fore.LIGHTCYAN_EX = ""
    colorama.Fore.LIGHTGREEN_EX = ""
    colorama.Fore.LIGHTMAGENTA_EX = ""
    colorama.Fore.LIGHTRED_EX = ""
    colorama.Fore.LIGHTWHITE_EX = ""
    colorama.Fore.LIGHTYELLOW_EX = ""
    colorama.Fore.MAGENTA = ""
    colorama.Fore.RED = ""
    colorama.Fore.RESET = ""
    colorama.Fore.WHITE = ""
    colorama.Fore.YELLOW = ""
    colorama.Style.BRIGHT = ""
    colorama.Style.DIM = ""


# TODO use "".join()
def format_dict_output(key_style, key, value_style, value):
    output =   ""
    output += f"{key_style}" if key_style else colorama.Style.NORMAL
    output += f"{key}: "
    output += f"{value_style}" if value_style else colorama.Style.NORMAL
    output += f"{value}"

    return output


def print_ip_api(ip_api_data):
    # name: key
    parameters = { "ISP":"isp", "ASN":"as", "Country Code":"countryCode",
                   "Country":"country", "Region Code":"region",
                   "Region":"regionName", "Zip Code":"zip",
                   "Time Zone":"timezone", "Latitude":"lat",
                   "Longitude":"lon" }

    print(f"{colorama.Style.BRIGHT}ip-api.com API Response:")

    for name, key in parameters.items():
        print(format_dict_output(key_style=colorama.Style.BRIGHT + colorama.Fore.WHITE,
                                 key=name,
                                 value_style=colorama.Fore.WHITE,
                                 value=ip_api_data[key]))
    print()


def print_shodan(api_data, target):
    print(f"{colorama.Fore.MAGENTA}{colorama.Style.BRIGHT}shodan.io API Response:")

    if "error" in api_data:
        print(f"{colorama.Fore.LIGHTRED_EX}{colorama.Style.BRIGHT}No data found for {target}\n")
        return

    # name: key
    parameters = { "Last Update":"last_update", "Open Ports":"ports",
                   "ISP":"isp", "Hostnames":"hostnames", "Country":"country",
                   "Latitude":"latitude", "Longitude":"longitude" }

    for name, key in parameters.items():
        print(format_dict_output(key_style=colorama.Style.BRIGHT + colorama.Fore.MAGENTA,
                                 key=name,
                                 value_style=colorama.Fore.MAGENTA,
                                 value=api_data[key] if key in api_data else "Not found"))
    print()


def print_virustotal(api_data, target, target_type):
    print(f"{colorama.Fore.LIGHTCYAN_EX}{colorama.Style.BRIGHT}VirusTotal API Response:")

    parameter_sets = [
        ["timeout", "Timed Out", colorama.Fore.WHITE],
        ["undetected", "Undetected", colorama.Fore.WHITE],
        ["harmless", "Harmless", colorama.Fore.GREEN],
        ["suspicious", "Suspicious", colorama.Fore.YELLOW],
        ["malicious", "Malicious", colorama.Fore.LIGHTRED_EX]
    ]

    for parameters in parameter_sets:
        print(format_dict_output(key_style=colorama.Style.BRIGHT + parameters[2],
                                 key=parameters[1],
                                 value_style=colorama.Style.NORMAL,
                                 value=api_data[parameters[0]]))

    if target_type == "address":
        print(f"{colorama.Fore.LIGHTCYAN_EX}https://www.virustotal.com/gui/ip-address/{target}/detection")
    elif target_type == "hash":
        print(f"{colorama.Fore.LIGHTCYAN_EX}https://www.virustotal.com/gui/file/{target}/detection")
    print()


def print_threatcrowd_ip(target_api_data, target):
    if "resolutions" in target_api_data and len(target_api_data["resolutions"]) > 0:
        print(f"{colorama.Fore.WHITE}{colorama.Style.DIM}Domains linked with {target} (first 25):")
        print(", ".join([ resolution["domain"] for resolution in target_api_data["resolutions"][:25] ]))
    else:
        print(f"{colorama.Fore.LIGHTRED_EX}{colorama.Style.BRIGHT}No domains found")

    print()

    if "hashes" in target_api_data and len(target_api_data["hashes"]) > 0:
        print(f"{colorama.Fore.WHITE}{colorama.Style.DIM}Hashes linked with {target} (first 25):")
        print(", ".join(target_api_data["hashes"][:25]))
    else:
        print(f"{colorama.Fore.LIGHTRED_EX}{colorama.Style.BRIGHT}No hashes found")
    print()


def print_threatcrowd_hash(target_api_data, target):
    if "scans" in target_api_data and len(target_api_data["scans"]) > 0:
        print(f"{colorama.Fore.WHITE}{colorama.Style.DIM}Scan results for {target} (first 25):")
        print(", ".join([ scan for scan in target_api_data["scans"][:25] if scan ]))
    else:
        print(f"{colorama.Fore.LIGHTRED_EX}{colorama.Style.BRIGHT}No scan results")

    if "domains" in target_api_data and len(target_api_data["domains"]) > 0:
        print(f"{colorama.Fore.WHITE}{colorama.Style.DIM}Domains linked with {target} (first 25):")
        print(", ".join([ domain for domain in target_api_data["domains"][:25] if domain ]))
    else:
        print(f"{colorama.Fore.LIGHTRED_EX}{colorama.Style.BRIGHT}No domains found")

    if "references" in target_api_data and len(target_api_data["references"]) > 0:
        print(f"{colorama.Fore.WHITE}{colorama.Style.DIM}References for {target} (first 25):")
        print(", ".join([ reference for reference in target_api_data["references"][:25] if reference ]))
    else:
        print(f"{colorama.Fore.LIGHTRED_EX}{colorama.Style.BRIGHT}No references found")
    print()


def print_threatcrowd(target_api_data, target, target_type):
    print(f"{colorama.Fore.YELLOW}{colorama.Style.BRIGHT}ThreatCrowd API Response:")

    if target_api_data["response_code"] == "0":
        print(f"{colorama.Fore.RED}{colorama.Style.BRIGHT}No results found for {target}\n")
        return

    try:
        if target_api_data["votes"] == 0:
            print(f"{colorama.Style.BRIGHT}{target} has even or no maliciousness votes.")
        elif target_api_data["votes"] == -1:
            print(f"{colorama.Fore.RED}{colorama.Style.BRIGHT}{target} has been voted malicious.")
        elif target_api_data["votes"] == 1:
            print(f"{colorama.Fore.GREEN}{colorama.Style.BRIGHT}{target} has been voted not malicious.")
        else:
            print(f'{colorama.Fore.LIGHTRED_EX}{colorama.Style.BRIGHT}Could not process vote data "{target_api_data["votes"]}" (expected -1, 0, or 1).')
    except KeyError:
        pass

    if target_type == "address":
        print_threatcrowd_ip(target_api_data, target)
    elif target_type == "hash":
        print_threatcrowd_hash(target_api_data, target)

    try:
        print(f'{colorama.Fore.YELLOW}{target_api_data["permalink"]}')
    except KeyError:
        pass

    print()


def print_alienvault_otx_ip(target_url_api_data, target_malware_api_data, target):
    # Process url data
    unique_domains = []
    for url_entry in target_url_api_data["url_list"]:
        if url_entry["domain"] not in unique_domains and len(url_entry["domain"]) > 0:
            unique_domains.append(url_entry["domain"])

    if len(unique_domains) > 0:
        print(f"{colorama.Style.BRIGHT}Domains linked to {target}:")
        for domain in unique_domains:
            print(domain)
    else:
        print(f"{colorama.Style.BRIGHT}{colorama.Fore.LIGHTRED_EX}No domains found for {target}")

    # Process malware data
    hashes = []
    detections = []
    for entry in target_malware_api_data["data"]:
        if entry["hash"] not in hashes:
            hashes.append(entry["hash"])
            detections.append(entry["detections"])

    output_lines = []
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
        print(f"{colorama.Style.BRIGHT}Hashes linked to {target}:")
        for line in output_lines:
            print(line)
    else:
        print(f"{colorama.Style.BRIGHT}{colorama.Fore.LIGHTRED_EX}No hashes found for {target}")

    print(f"{colorama.Fore.LIGHTBLACK_EX}https://otx.alienvault.com/indicator/ip/{target}\n")


def print_alienvault_otx_hash(general_data, analysis_data, target):
    pulse_data = general_data["pulse_info"]
    pulses = pulse_data["pulses"]

    names = [ pulse["name"] for pulse in pulses ]
    descriptions = [ pulse["description"] for pulse in pulses ]
    tags = list(itertools.chain.from_iterable([ pulse["tags"] for pulse in pulses ]))
    malware_families = list(itertools.chain.from_iterable(
                            [ v["malware_families"] for v in pulse_data["related"].values() ]))
    adversaries = list(itertools.chain.from_iterable(
                       [ v["adversary"] for v in pulse_data["related"].values() ]))

    general_output = {
        "Pulse count": pulse_data["count"],
        "Pulse names": ", ".join(names) if len(names) > 0 else "No names found",
        "Pulse tags": ", ".join(tags) if len(tags) > 0 else "No tags found",
        "Pulse descriptions": str(descriptions).strip("[]") if len(descriptions) > 0 else "No descriptions available",
        "Malware families": ", ".join(malware_families) if len(malware_families) > 0 else "No malware families identified",
        "Adversaries": ", ".join(adversaries) if len(adversaries) > 0 else "No adversaries identified"
    }

    if analysis_data["analysis"]:
        analysis_info = analysis_data["analysis"]["info"]["results"]
        analysis_plugins = analysis_data["analysis"]["plugins"]
        analysis_pe32info = analysis_plugins["pe32info"]["results"]
        analysis_yarad = analysis_plugins["yarad"]["results"]
        analysis_peanomal = analysis_plugins["peanomal"]["results"]

        packers = analysis_pe32info["packers"] if analysis_pe32info["packers"] else []
        yara_rule_names = [ x["rule_name"] for x in analysis_yarad["detection"] ]

    try:
        analysis_output = {
            "File class": analysis_info["file_class"],
            "File type": analysis_info["file_type"],
            "File size": str(analysis_info["filesize"]) + " bytes",
            "MD5 hash": analysis_info["md5"],
            "SHA1 hash": analysis_info["sha1"],
            "SHA256 hash": analysis_info["sha256"],
            "SSDeep hash": analysis_info["ssdeep"],
            "ImpHash": analysis_pe32info["imphash"],
            "PEHash": analysis_pe32info["pehash"],
            "Rich PEHash": analysis_pe32info["richhash"] if "richhash" in analysis_pe32info else "No Rich PEHash",
            "Anomalies detected by PEAnomal": analysis_peanomal["anomalies"],
            "YARA compression rule detections": sum(1 for x in analysis_yarad["detection"]
                                                    if "category" in x and "compression" in x["category"]),
            "YARA code overlap rule detections": sum(1 for x in analysis_yarad["detection"]
                                                     if "category" in x and "CodeOverlap" in x["category"]),
            "Packers": ", ".join(packers) if len(packers) > 0 else "No packers detected",
            "YARA rule detection names": ", ".join(yara_rule_names) if len(yara_rule_names) > 0 else "No YARA rules detected"
        }
    except NameError: # catch having no definitions from no analysis above
        analysis_output = None

    print("General data:")
    for key, value in general_output.items():
        print(format_dict_output(key_style=colorama.Style.BRIGHT,
                                 key=key,
                                 value_style=None,
                                 value=value))

    print()

    if analysis_output:
        print("Analysis data:")
        for key, value in analysis_output.items():
            print(format_dict_output(key_style=colorama.Style.BRIGHT,
                                     key=key,
                                     value_style=None,
                                     value=value))
    else:
        print(f"No analysis data available for {target}")

    print(f"{colorama.Fore.LIGHTBLACK_EX}https://otx.alienvault.com/indicator/file/{target}\n")


def print_alienvault_otx(alienvault_otx_data, target, target_type):
    print(f"{colorama.Fore.LIGHTBLACK_EX}{colorama.Style.BRIGHT}AlienVault OTX API Response:")

    if target_type == "address":
        print_alienvault_otx_ip(alienvault_otx_data["url"], alienvault_otx_data["malware"], target)
    else:
        print_alienvault_otx_hash(alienvault_otx_data["general"], alienvault_otx_data["analysis"], target)
    print()


def print_target_data(target_data_dict):
    target = target_data_dict["target"]
    target_type = target_data_dict["target_type"]
    target_api_data = target_data_dict["target_api_data"]

    print(f"{colorama.Style.BRIGHT}{'-'*20}")
    print(f"{colorama.Style.BRIGHT}API Report for {target}")
    print(f"{colorama.Style.BRIGHT}{'-'*20}")

    if "ip_api" in target_api_data:
        print_ip_api(target_api_data["ip_api"])

    if "shodan" in target_api_data:
        print_shodan(target_api_data["shodan"], target)

    if "virustotal" in target_api_data:
        print_virustotal(target_api_data["virustotal"], target, target_type)

    if "threatcrowd" in target_api_data:
        print_threatcrowd(target_api_data["threatcrowd"], target, target_type)

    if "alienvault_otx" in target_api_data:
        print_alienvault_otx(target_api_data["alienvault_otx"], target, target_type)

    if "xforce" in target_api_data:
        print_xforce(target_api_data["xforce"], target, target_type)

    print(f"{colorama.Style.BRIGHT}{'-'*20}")
    print(f"{colorama.Style.BRIGHT}End of API Report for {target}")
    print(f"{colorama.Style.BRIGHT}{'-'*20}")
    print()
