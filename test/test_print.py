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
import unittest

from contextlib import redirect_stdout
from io import StringIO

import mapis_requests # need dummy responses to print

from mapis_data import add_api_data
from mapis_print import *

class TestColorToggle(unittest.TestCase):
    def test_color_toggle(self):
        original_black = colorama.Fore.BLACK
        self.assertNotEqual(colorama.Fore.BLACK, "")
        disable_color()
        self.assertEqual(colorama.Fore.BLACK, "")
        enable_color()
        self.assertEqual(colorama.Fore.BLACK, original_black)


class TestFormatDictOutput(unittest.TestCase):
    def test_format_dict_output(self):
        style = PrintStyle(
            key_style = colorama.Style.BRIGHT,
            key_color = colorama.Fore.WHITE,
            value_color = colorama.Fore.WHITE
        )
        ks = style.key_style
        kc = style.key_color
        k = "test_key"
        vs = style.value_style
        vc = style.value_color
        v = "test_value"
        self.assertEqual(
            f"{ks}{kc}{k}{colorama.Style.NORMAL}{colorama.Fore.RESET}: {vs}{vc}{v}",
            format_dict_output(k, v, style)
        )

        vc = style.value_color = colorama.Fore.RED
        self.assertEqual(
            f"{ks}{kc}{k}{colorama.Style.NORMAL}{colorama.Fore.RESET}: {vs}{vc}{v}",
            format_dict_output(k, v, style)
        )


class TestIPAPIConstants(unittest.TestCase):
    def test_ip_api_style(self):
        self.assertEqual(
            IPAPIStyle.ANNOUNCE,
            colorama.Style.BRIGHT
        )
        self.assertEqual(
            IPAPIStyle.ENTRY,
            PrintStyle(
                key_style=colorama.Style.BRIGHT,
                key_color=colorama.Fore.WHITE,
                value_color=colorama.Fore.WHITE)
        )
    

    def test_ip_api_strings(self):
        self.assertEqual(
            IPAPIStrings.ANNOUNCE,
            IPAPIStyle.ANNOUNCE + "ip-api.com API Response:"
        )


class TestPrintIPAPI(unittest.TestCase):
    target_address = "127.0.0.1"

    def test_print_ip_api_address(self):
        data = mapis_requests.request_ip_api(
            self.target_address, "address", dry_run=True).json()

        with redirect_stdout(StringIO()) as output:
            print_ip_api(data)

        expected_dict_output = (
            format_dict_output(name, data[key], IPAPIStyle.ENTRY)
            for name, key in IP_API_PARAMS.items()
        )

        expected = "\n".join((
            IPAPIStrings.ANNOUNCE,
            *expected_dict_output,
            "",
            ""
        ))
        self.assertEqual(output.getvalue(), expected)


class TestShodanConstants(unittest.TestCase):
    def test_shodan_style(self):
        self.assertEqual(
            ShodanStyle.ANNOUNCE,
            colorama.Fore.MAGENTA + colorama.Style.BRIGHT
        )
        self.assertEqual(
            ShodanStyle.NO_DATA,
            colorama.Fore.LIGHTRED_EX + colorama.Style.BRIGHT
        )
        self.assertEqual(
            ShodanStyle.ENTRY,
            PrintStyle(
                key_style=colorama.Style.BRIGHT,
                key_color=colorama.Fore.MAGENTA,
                value_color=colorama.Fore.MAGENTA
            )
        )
    

    def test_shodan_strings(self):
        self.assertEqual(
            ShodanStrings.ANNOUNCE,
            ShodanStyle.ANNOUNCE + "shodan.io API Response:"
        )
        self.assertEqual(
            ShodanStrings.NO_DATA,
            ShodanStyle.NO_DATA + "No data found for {target}"
        )


class TestPrintShodan(unittest.TestCase):
    target_address = "127.0.0.1"

    def test_print_shodan(self):
        data = mapis_requests.request_shodan(
            self.target_address, "address", None, dry_run=True).json()

        with redirect_stdout(StringIO()) as output:
            print_shodan(data, self.target_address)

        expected_dict_output = (
            format_dict_output(name, data[key], ShodanStyle.ENTRY)
            for name, key in SHODAN_PARAMS.items()
        )

        expected = "\n".join((
            ShodanStrings.ANNOUNCE,
            *expected_dict_output,
            "",
            ""
        ))
        self.assertEqual(output.getvalue(), expected)


    def test_print_shodan_error(self):
        data = {"error": True}
        with redirect_stdout(StringIO()) as output:
            print_shodan(data, self.target_address)
        
        expected_shodan = "\n".join((
            ShodanStrings.ANNOUNCE,
            ShodanStrings.NO_DATA.format(target=self.target_address),
            "",
            ""
        ))

        self.assertEqual(output.getvalue(), expected_shodan)


class TestVirusTotalConstants(unittest.TestCase):
    def test_virustotal_style(self):
        self.assertEqual(
            VirusTotalStyle.ANNOUNCE,
            colorama.Fore.LIGHTCYAN_EX + colorama.Style.BRIGHT
        )
        self.assertEqual(
            VirusTotalStyle.PERMALINK,
            colorama.Fore.LIGHTCYAN_EX
        )

        self.assertEqual(
            VirusTotalStyle.TIMEOUT,
            PrintStyle(
                key_style = colorama.Style.BRIGHT,
                key_color = colorama.Fore.WHITE)
        )
        self.assertEqual(
            VirusTotalStyle.UNDETECTED,
            PrintStyle(
                key_style = colorama.Style.BRIGHT,
                key_color = colorama.Fore.WHITE)
        )
        self.assertEqual(
            VirusTotalStyle.HARMLESS,
            PrintStyle(
                key_style = colorama.Style.BRIGHT,
                key_color = colorama.Fore.GREEN)
        )
        self.assertEqual(
            VirusTotalStyle.SUSPICIOUS,
            PrintStyle(
                key_style = colorama.Style.BRIGHT,
                key_color = colorama.Fore.YELLOW)
        )
        self.assertEqual(
            VirusTotalStyle.MALICIOUS,
            PrintStyle(
                key_style = colorama.Style.BRIGHT,
                key_color = colorama.Fore.LIGHTRED_EX)
        )
    

    def test_virustotal_strings(self):
        self.assertEqual(
            VirusTotalStrings.ANNOUNCE,
            VirusTotalStyle.ANNOUNCE + "VirusTotal API Response:"
        )
        self.assertEqual(
            VirusTotalStrings.PERMALINK_ADDRESS,
            VirusTotalStyle.PERMALINK + "https://www.virustotal.com/gui/ip-address/{target}/detection"
        )
        self.assertEqual(
            VirusTotalStrings.PERMALINK_HASH,
            VirusTotalStyle.PERMALINK + "https://www.virustotal.com/gui/file/{target}/detection"
        )
    

class TestPrintVirusTotal(unittest.TestCase):
    target_address = "127.0.0.1"
    target_hash = "00000000000000000000000000000000"

    def test_print_virustotal_address(self):
        data = mapis_requests.request_virustotal(
            None, self.target_address, "address", dry_run=True)
        with redirect_stdout(StringIO()) as output:
            print_virustotal(data, self.target_address, "address")

        expected_dict_output = (
            format_dict_output(name, data[key], style)
            for key, name, style in VIRUSTOTAL_PARAMS
        )

        expected = "\n".join((
            VirusTotalStrings.ANNOUNCE,
            *expected_dict_output,
            VirusTotalStrings.PERMALINK_ADDRESS.format(target=self.target_address),
            "",
            ""
        ))
        self.assertEqual(output.getvalue(), expected)


    def test_print_virustotal_hash(self):
        data = mapis_requests.request_virustotal(
            None, self.target_hash, "hash", dry_run=True)
        with redirect_stdout(StringIO()) as output:
            print_virustotal(data, self.target_hash, "hash")

        expected_dict_output = (
            format_dict_output(name, data[key], style)
            for key, name, style in VIRUSTOTAL_PARAMS
        )

        expected = "\n".join((
            VirusTotalStrings.ANNOUNCE,
            *expected_dict_output,
            VirusTotalStrings.PERMALINK_HASH.format(target=self.target_hash),
            "",
            ""
        ))
        self.assertEqual(output.getvalue(), expected)


class TestThreatCrowdConstants(unittest.TestCase):
    def test_threatcrowd_style(self):
        self.assertEqual(
            ThreatCrowdStyle.ANNOUNCE,
            colorama.Fore.YELLOW + colorama.Style.BRIGHT
        )
        self.assertEqual(
            ThreatCrowdStyle.NO_RESPONSE,
            colorama.Fore.RED + colorama.Style.BRIGHT
        )

        self.assertEqual(
            ThreatCrowdStyle.SECTION_ANNOUNCE,
            colorama.Fore.WHITE + colorama.Style.DIM
        )
        self.assertEqual(
            ThreatCrowdStyle.SECTION_EMPTY,
            colorama.Fore.LIGHTRED_EX + colorama.Style.BRIGHT
        )

        self.assertEqual(
            ThreatCrowdStyle.ALIAS_ENTRY,
            PrintStyle(
                key_style=colorama.Style.BRIGHT,
                key_color=colorama.Fore.WHITE)
        )
    

    def test_threatcrowd_strings(self):
        self.assertEqual(
            ThreatCrowdStrings.ANNOUNCE,
            ThreatCrowdStyle.ANNOUNCE + "ThreatCrowd API Response:"
        )
        self.assertEqual(
            ThreatCrowdStrings.NO_RESPONSE,
            ThreatCrowdStyle.NO_RESPONSE + "No results found for {target}"
        )

        self.assertEqual(
            ThreatCrowdStrings.DOMAIN_ANNOUNCE,
            ThreatCrowdStyle.SECTION_ANNOUNCE + "Domains linked with {target} (first 25):"
        )
        self.assertEqual(
            ThreatCrowdStrings.DOMAIN_EMPTY,
            ThreatCrowdStyle.SECTION_EMPTY + "No domains found"
        )
        self.assertEqual(
            ThreatCrowdStrings.HASH_ANNOUNCE,
            ThreatCrowdStyle.SECTION_ANNOUNCE + "Hashes linked with {target} (first 25):"
        )
        self.assertEqual(
            ThreatCrowdStrings.HASH_EMPTY,
            ThreatCrowdStyle.SECTION_EMPTY + "No hashes found"
        )
        """
        self.assertEqual(
            ThreatCrowdStrings.PERMALINK_ADDRESS,
            ThreatCrowdStyle.PERMALINK + "http://ci-www.threatcrowd.org/ip.php?ip={target}"
        )
        """

        self.assertEqual(
            ThreatCrowdStrings.ALIAS_ANNOUNCE,
            ThreatCrowdStyle.SECTION_ANNOUNCE + "Alias hashes for {target}:"
        )
        self.assertEqual(
            ThreatCrowdStrings.SCAN_ANNOUNCE,
            ThreatCrowdStyle.SECTION_ANNOUNCE + "Scan results for {target} (first 25):"
        )
        self.assertEqual(
            ThreatCrowdStrings.SCAN_EMPTY,
            ThreatCrowdStyle.SECTION_EMPTY + "No scan results"
        )
        self.assertEqual(
            ThreatCrowdStrings.ADDRESSES_ANNOUNCE,
            ThreatCrowdStyle.SECTION_ANNOUNCE + "IP addresses linked with {target} (first 25):"
        )
        self.assertEqual(
            ThreatCrowdStrings.ADDRESSES_EMPTY,
            ThreatCrowdStyle.SECTION_EMPTY + "No related IP addresses"
        )
        self.assertEqual(
            ThreatCrowdStrings.REFERENCE_ANNOUNCE,
            ThreatCrowdStyle.SECTION_ANNOUNCE + "References for {target} (first 25):"
        )
        self.assertEqual(
            ThreatCrowdStrings.REFERENCE_EMPTY,
            ThreatCrowdStyle.SECTION_EMPTY + "No references found"
        )
        """
        self.assertEqual(
            ThreatCrowdStrings.PERMALINK_HASH,
            ThreatCrowdStyle.PERMALINK + "http://ci-www.threatcrowd.org/malware.php?md5={target}"
        )
        """


class TestPrintThreatCrowd(unittest.TestCase):
    target_address = "127.0.0.1"
    target_hash = "00000000000000000000000000000000"

    def test_print_threatcrowd_address(self):
        data = mapis_requests.request_threatcrowd(
            self.target_address, "address", dry_run=True).json()

        with redirect_stdout(StringIO()) as output:
            print_threatcrowd(data, self.target_address, "address")

        expected = "\n".join((
            ThreatCrowdStrings.ANNOUNCE,
            ThreatCrowdStrings.MaliciousVote.MAYBE.format(target=self.target_address),
            "",
            ThreatCrowdStrings.DOMAIN_ANNOUNCE.format(target=self.target_address),
            "example.com (resolved 2020-01-01), example.org (resolved 2020-01-01)",
            "",
            ThreatCrowdStrings.HASH_ANNOUNCE.format(target=self.target_address),
            "00000000000000000000000000000000, 11111111111111111111111111111111, 22222222222222222222222222222222, 33333333333333333333333333333333",
            "",
            ThreatCrowdStyle.PERMALINK + data["permalink"],
            "",
            ""
        ))
        self.assertEqual(output.getvalue(), expected)


    def test_print_threatcrowd_hash(self):
        data = mapis_requests.request_threatcrowd(
            self.target_hash, "hash", dry_run=True).json()

        with redirect_stdout(StringIO()) as output:
            print_threatcrowd(data, self.target_hash, "hash")

        expected = "\n".join((
            ThreatCrowdStrings.ANNOUNCE,
            ThreatCrowdStrings.MaliciousVote.MAYBE.format(target=self.target_hash),
            "",
            ThreatCrowdStrings.ALIAS_ANNOUNCE.format(target=self.target_hash),
            format_dict_output("MD5", data["md5"], ThreatCrowdStyle.ALIAS_ENTRY),
            format_dict_output("SHA1", data["sha1"], ThreatCrowdStyle.ALIAS_ENTRY),
            "",
            ThreatCrowdStrings.SCAN_ANNOUNCE.format(target=self.target_hash),
            "Trojan.Win32, Trojan, Backdoor:Win32",
            "",
            ThreatCrowdStrings.DOMAIN_ANNOUNCE.format(target=self.target_hash),
            "example.com, example.org",
            "",
            ThreatCrowdStrings.ADDRESSES_ANNOUNCE.format(target=self.target_hash),
            "10.0.0.1, 192.168.0.1, 172.16.0.1",
            "",
            ThreatCrowdStrings.REFERENCE_ANNOUNCE.format(target=self.target_hash),
            "https://example.com, https://example.org",
            "",
            ThreatCrowdStyle.PERMALINK + data["permalink"],
            "",
            ""
        ))
        self.assertEqual(output.getvalue(), expected)


    def test_print_threatcrowd_address_no_response(self):
        data = {"response_code": "0"}

        with redirect_stdout(StringIO()) as output:
            print_threatcrowd(data, self.target_address, "address")

        expected = "\n".join((
            ThreatCrowdStrings.ANNOUNCE,
            ThreatCrowdStrings.NO_RESPONSE.format(target=self.target_address),
            "",
            ""
        ))
        self.assertEqual(output.getvalue(), expected)


    def test_print_threatcrowd_hash_no_response(self):
        data = {"response_code": "0"}

        with redirect_stdout(StringIO()) as output:
            print_threatcrowd(data, self.target_hash, "hash")

        expected = "\n".join((
            ThreatCrowdStrings.ANNOUNCE,
            ThreatCrowdStrings.NO_RESPONSE.format(target=self.target_hash),
            "",
            ""
        ))


    def test_print_threatcrowd_address_empty(self):
        data = {
            "response_code": "1",
            "votes": "0",
            "resolutions": [],
            "hashes": [],
            "permalink": f"http://ci-www.threatcrowd.org/ip.php?ip={self.target_address}"
        }

        with redirect_stdout(StringIO()) as output:
            print_threatcrowd(data, self.target_address, "address")

        expected = "\n".join((
            ThreatCrowdStrings.ANNOUNCE,
            ThreatCrowdStrings.MaliciousVote.MAYBE.format(target=self.target_address),
            "",
            ThreatCrowdStrings.DOMAIN_EMPTY,
            "",
            ThreatCrowdStrings.HASH_EMPTY,
            "",
            ThreatCrowdStyle.PERMALINK + data["permalink"],
            "",
            ""
        ))
        self.assertEqual(output.getvalue(), expected)


    def test_print_threatcrowd_hash_empty(self):
        data = mapis_requests.request_threatcrowd(
            self.target_hash, "hash", dry_run=True).json()
        data["scans"] = list()
        data["domains"] = list()
        data["ips"] = list()
        data["references"] = list()

        with redirect_stdout(StringIO()) as output:
            print_threatcrowd(data, self.target_hash, "hash")

        expected = "\n".join((
            ThreatCrowdStrings.ANNOUNCE,
            ThreatCrowdStrings.MaliciousVote.MAYBE.format(target=self.target_hash),
            "",
            ThreatCrowdStrings.ALIAS_ANNOUNCE.format(target=self.target_hash),
            format_dict_output("MD5", data["md5"], ThreatCrowdStyle.ALIAS_ENTRY),
            format_dict_output("SHA1", data["sha1"], ThreatCrowdStyle.ALIAS_ENTRY),
            "",
            ThreatCrowdStrings.SCAN_EMPTY,
            "",
            ThreatCrowdStrings.DOMAIN_EMPTY,
            "",
            ThreatCrowdStrings.ADDRESSES_EMPTY,
            "",
            ThreatCrowdStrings.REFERENCE_EMPTY,
            "",
            ThreatCrowdStyle.PERMALINK + data["permalink"],
            "",
            ""
        ))
        self.assertEqual(output.getvalue(), expected)


    def test_print_threatcrowd_maybe_malicious(self):
        data = mapis_requests.request_threatcrowd(
            self.target_hash, "hash", dry_run=True).json()
        data["votes"] = "0"
        with redirect_stdout(StringIO()) as output:
            print_threatcrowd(data, self.target_hash, "hash")
        vote_output = output.getvalue().splitlines()[1]
        expected = ThreatCrowdStrings.MaliciousVote.MAYBE.format(target=self.target_hash)
        self.assertEqual(vote_output, expected)


    def test_print_threatcrowd_malicious(self):
        data = mapis_requests.request_threatcrowd(
            self.target_hash, "hash", dry_run=True).json()
        data["votes"] = "-1"
        with redirect_stdout(StringIO()) as output:
            print_threatcrowd(data, self.target_hash, "hash")
        vote_output = output.getvalue().splitlines()[1]
        expected = ThreatCrowdStrings.MaliciousVote.YES.format(target=self.target_hash)
        self.assertEqual(vote_output, expected)


    def test_print_threatcrowd_not_malicious(self):
        data = mapis_requests.request_threatcrowd(
            self.target_hash, "hash", dry_run=True).json()
        data["votes"] = "1"
        with redirect_stdout(StringIO()) as output:
            print_threatcrowd(data, self.target_hash, "hash")
        vote_output = output.getvalue().splitlines()[1]
        expected = ThreatCrowdStrings.MaliciousVote.NO.format(target=self.target_hash)
        self.assertEqual(vote_output, expected)


    def test_print_threatcrowd_malicious_unavailable(self):
        data = mapis_requests.request_threatcrowd(
            self.target_hash, "hash", dry_run=True).json()
        data["votes"] = "invalid"
        with redirect_stdout(StringIO()) as output:
            print_threatcrowd(data, self.target_hash, "hash")
        vote_output = output.getvalue().splitlines()[1]
        expected = ThreatCrowdStrings.MaliciousVote.UNAVAILABLE.format(given=data["votes"])
        self.assertEqual(vote_output, expected)


class TestAlientVaultOTXConstants(unittest.TestCase):
    def test_alientvault_otx_style(self):
        self.assertEqual(
            AlienVaultOTXStyle.ANNOUNCE,
            colorama.Fore.LIGHTBLACK_EX + colorama.Style.BRIGHT
        )
        self.assertEqual(
            AlienVaultOTXStyle.SECTION_ANNOUNCE,
            colorama.Fore.LIGHTBLACK_EX
        )
        self.assertEqual(
            AlienVaultOTXStyle.SECTION_EMPTY,
            colorama.Fore.LIGHTRED_EX
        )

        self.assertEqual(
            AlienVaultOTXStyle.GENERAL_ENTRY,
            PrintStyle(key_style=colorama.Style.BRIGHT)
        )
        self.assertEqual(
            AlienVaultOTXStyle.ANALYSIS_ENTRY,
            PrintStyle(key_style=colorama.Style.BRIGHT)
        )

        self.assertEqual(
            AlienVaultOTXStyle.PERMALINK,
            colorama.Fore.LIGHTBLACK_EX + colorama.Style.BRIGHT
        )


    def test_alientvault_otx_strings(self):
        self.assertEqual(
            AlienVaultOTXStrings.ANNOUNCE,
            AlienVaultOTXStyle.ANNOUNCE + "AlienVault OTX API Response:"
        )

        self.assertEqual(
            AlienVaultOTXStrings.DOMAIN_ANNOUNCE,
            AlienVaultOTXStyle.SECTION_ANNOUNCE + "Domains linked to {target}:"
        )
        self.assertEqual(
            AlienVaultOTXStrings.DOMAIN_EMPTY,
            AlienVaultOTXStyle.SECTION_EMPTY + "No domains found for {target}"
        )
        self.assertEqual(
            AlienVaultOTXStrings.HASH_ANNOUNCE,
            AlienVaultOTXStyle.SECTION_ANNOUNCE + "Hashes linked to {target}:"
        )
        self.assertEqual(
            AlienVaultOTXStrings.HASH_EMPTY,
            AlienVaultOTXStyle.SECTION_EMPTY + "No hashes found for {target}"
        )

        self.assertEqual(
            AlienVaultOTXStrings.GENERAL_ANNOUNCE,
            AlienVaultOTXStyle.SECTION_ANNOUNCE + "General data for {target}:"
        )
        self.assertEqual(
            AlienVaultOTXStrings.GENERAL_EMPTY,
            AlienVaultOTXStyle.SECTION_EMPTY + "No general data for {target}"
        )
        self.assertEqual(
            AlienVaultOTXStrings.ANALYSIS_ANNOUNCE,
            AlienVaultOTXStyle.SECTION_ANNOUNCE + "Analysis data for {target}:"
        )
        self.assertEqual(
            AlienVaultOTXStrings.ANALYSIS_EMPTY,
            AlienVaultOTXStyle.SECTION_EMPTY + "No analysis data for {target}"
        )

        self.assertEqual(
            AlienVaultOTXStrings.PERMALINK_ADDRESS,
            AlienVaultOTXStyle.PERMALINK + "https://otx.alienvault.com/indicator/ip/{target}"
        )
        self.assertEqual(
            AlienVaultOTXStrings.PERMALINK_HASH,
            AlienVaultOTXStyle.PERMALINK + "https://otx.alienvault.com/indicator/file/{target}"
        )


class TestAlienVaultOTX(unittest.TestCase):
    target_address = "127.0.0.1"
    target_hash = "00000000000000000000000000000000"

    def test_print_alienvault_otx_address(self):
        data_tuple = mapis_requests.request_alienvault_otx(
            self.target_address, "address", dry_run=True)
        data = {"url": data_tuple[0].json(), "malware": data_tuple[1].json()}
        with redirect_stdout(StringIO()) as output:
            print_alienvault_otx(data, self.target_address, "address")
        expected = "\n".join((
            AlienVaultOTXStrings.ANNOUNCE,
            AlienVaultOTXStrings.DOMAIN_ANNOUNCE.format(target=self.target_address),
            "example.com",
            "example.org",
            "",
            AlienVaultOTXStrings.HASH_ANNOUNCE.format(target=self.target_address),
            "0000000000000000000000000000000000000000000000000000000000000000:TEST_NAME_1,TEST_NAME_2",
            "1111111111111111111111111111111111111111111111111111111111111111:TEST_NAME_3",
            "",
            AlienVaultOTXStrings.PERMALINK_ADDRESS.format(target=self.target_address),
            "",
            ""
        ))
        self.assertEqual(output.getvalue(), expected)


    def test_print_alienvault_otx_hash(self):
        data_tuple = mapis_requests.request_alienvault_otx(
            self.target_hash, "hash", dry_run=True)
        data = {"general": data_tuple[0].json(), "analysis": data_tuple[1].json()}
        with redirect_stdout(StringIO()) as output:
            print_alienvault_otx(data, self.target_hash, "hash")

        general_data = data["general"]
        pulse_data = general_data["pulse_info"]
        pulses = pulse_data["pulses"]

        names = [ pulse["name"] for pulse in pulses ]
        descriptions = [ pulse["description"] for pulse in pulses ]
        tags = list(itertools.chain.from_iterable((pulse["tags"] for pulse in pulses)))
        malware_families = list(itertools.chain.from_iterable((
            v["malware_families"] for v in pulse_data["related"].values()
        )))
        adversaries = list(itertools.chain.from_iterable((
            v["adversary"] for v in pulse_data["related"].values()
        )))
        general_output = {
            "Pulse count": pulse_data.get("count", "0"),
            "Pulse names": ", ".join(names) if names else "No names found",
            "Pulse tags": ", ".join(tags) if tags else "No tags found",
            "Pulse descriptions": ", ".join(( f'"{d}"' for d in descriptions)) if descriptions else "No descriptions available",
            "Malware families": ", ".join(malware_families) if malware_families else "No malware families identified",
            "Adversaries": ", ".join(adversaries) if adversaries else "No adversaries identified"
        }

        analysis_data = data["analysis"]
        if analysis_data["analysis"]:
            analysis_info = analysis_data["analysis"]["info"]["results"]
            analysis_plugins = analysis_data["analysis"]["plugins"]
            analysis_pe32info = analysis_plugins["pe32info"]["results"]
            analysis_yarad = analysis_plugins["yarad"]["results"]
            analysis_peanomal = analysis_plugins["peanomal"]["results"]

        packers = analysis_pe32info.get("packers")
        yara_rule_names = [ x["rule_name"] for x in analysis_yarad["detection"] ]

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

        expected = "\n".join((
            AlienVaultOTXStrings.ANNOUNCE,
            AlienVaultOTXStrings.GENERAL_ANNOUNCE.format(target=self.target_hash),
            *(
                format_dict_output(key, value, AlienVaultOTXStyle.GENERAL_ENTRY)
                for key, value in general_output.items()
            ),
            "",
            AlienVaultOTXStrings.ANALYSIS_ANNOUNCE.format(target=self.target_hash),
            *(
                format_dict_output(key, value, AlienVaultOTXStyle.ANALYSIS_ENTRY)
                for key, value in analysis_output.items()
            ),
            "",
            AlienVaultOTXStrings.PERMALINK_HASH.format(target=self.target_hash),
            "",
            ""
        ))
        self.assertEqual(output.getvalue(), expected)


    def test_print_alienvault_otx_address_empty(self):
        data = {"url": {}, "malware": {}}
        with redirect_stdout(StringIO()) as output:
            print_alienvault_otx(data, self.target_address, "address")
        expected = "\n".join((
            AlienVaultOTXStrings.ANNOUNCE,
            AlienVaultOTXStrings.DOMAIN_EMPTY.format(target=self.target_address),
            "",
            AlienVaultOTXStrings.HASH_EMPTY.format(target=self.target_address),
            "",
            AlienVaultOTXStrings.PERMALINK_ADDRESS.format(target=self.target_address),
            "",
            ""
        ))
        self.assertEqual(output.getvalue(), expected)


    def test_print_alienvault_otx_hash_empty(self):
        data = {"general": {}, "analysis": {}}
        with redirect_stdout(StringIO()) as output:
            print_alienvault_otx(data, self.target_hash, "hash")
        general_output = {
            "Pulse count": "0",
            "Pulse names": "No names found",
            "Pulse tags": "No tags found",
            "Pulse descriptions": "No descriptions available",
            "Malware families": "No malware families identified",
            "Adversaries": "No adversaries identified"
        }
        expected = "\n".join((
            AlienVaultOTXStrings.ANNOUNCE,
            AlienVaultOTXStrings.GENERAL_ANNOUNCE.format(target=self.target_hash),
            *(
                format_dict_output(key, value, AlienVaultOTXStyle.GENERAL_ENTRY)
                for key, value in general_output.items()
            ),
            "",
            AlienVaultOTXStrings.ANALYSIS_EMPTY.format(target=self.target_hash),
            "",
            AlienVaultOTXStrings.PERMALINK_HASH.format(target=self.target_hash),
            "",
            ""
        ))
        self.maxDiff = None
        self.assertEqual(output.getvalue(), expected)


class TestPrintTargetConstants(unittest.TestCase):
    def test_print_target_style(self):
        self.assertEqual(
            PrintTargetStyle.DIVIDER,
            colorama.Style.BRIGHT
        )
        self.assertEqual(
            PrintTargetStyle.ANNOUNCE,
            colorama.Style.BRIGHT
        )
        self.assertEqual(
            PrintTargetStyle.EMPTY,
            colorama.Style.BRIGHT + colorama.Fore.LIGHTRED_EX
        )
        self.assertEqual(
            PrintTargetStyle.FINISH,
            colorama.Style.BRIGHT
        )


    def test_print_target_strings(self):
        self.assertEqual(
            PrintTargetStrings.DIVIDER,
            PrintTargetStyle.DIVIDER + "-"*20
        )
        self.assertEqual(
            PrintTargetStrings.ANNOUNCE,
            "\n".join((
                PrintTargetStrings.DIVIDER,
                PrintTargetStyle.ANNOUNCE + "Report for {target}",
                PrintTargetStrings.DIVIDER
            ))
        )
        self.assertEqual(
            PrintTargetStrings.EMPTY,
            "\n".join((
                PrintTargetStrings.DIVIDER,
                PrintTargetStyle.EMPTY + "No data available for {target}",
                PrintTargetStrings.DIVIDER
            ))
        )
        self.assertEqual(
            PrintTargetStrings.FINISH,
            "\n".join((
                PrintTargetStrings.DIVIDER,
                PrintTargetStyle.FINISH + "End of report for {target}",
                PrintTargetStrings.DIVIDER
            ))
        )


class TestPrintTarget(unittest.TestCase):
    target_address = "127.0.0.1"
    target_hash = "00000000000000000000000000000000"

    def test_print_target_address(self):
        api_data = dict()
        add_api_data("ip_api", api_data, mapis_requests.request_ip_api(
                self.target_address, "address", dry_run=True), self.target_address)
        add_api_data("shodan", api_data, mapis_requests.request_shodan(
                self.target_address, "address", key=None, dry_run=True), self.target_address)
        add_api_data("vt", api_data, mapis_requests.request_virustotal(
                None, self.target_address, "address", dry_run=True), self.target_address)
        add_api_data("tc", api_data, mapis_requests.request_threatcrowd(
                self.target_address, "address", dry_run=True), self.target_address)
        add_api_data("otx", api_data, mapis_requests.request_alienvault_otx(
                self.target_address, "address", dry_run=True), self.target_address)

        with redirect_stdout(StringIO()) as output:
            target_data = {
                "target": self.target_address,
                "target_type": "address",
                "target_api_data": api_data
            }
            print_target_data(target_data)

        with redirect_stdout(StringIO()) as ip_api_output:
            print_ip_api(api_data["ip_api"])
        with redirect_stdout(StringIO()) as shodan_output:
            print_shodan(api_data["shodan"], self.target_address)
        with redirect_stdout(StringIO()) as vt_output:
            print_virustotal(api_data["vt"], self.target_address, "address")
        with redirect_stdout(StringIO()) as tc_output:
            print_threatcrowd(api_data["tc"], self.target_address, "address")
        with redirect_stdout(StringIO()) as otx_output:
            print_alienvault_otx(api_data["otx"], self.target_address, "address")

        expected = "".join((
            PrintTargetStrings.ANNOUNCE.format(target=self.target_address) + "\n\n",
            ip_api_output.getvalue(),
            shodan_output.getvalue(),
            vt_output.getvalue(),
            tc_output.getvalue(),
            otx_output.getvalue(),
            PrintTargetStrings.FINISH.format(target=self.target_address) + "\n\n"
        ))
        self.assertEqual(output.getvalue(), expected)


    def test_print_target_hash(self):
        api_data = dict()
        add_api_data("vt", api_data, mapis_requests.request_virustotal(
            None, self.target_hash, "hash", dry_run=True), self.target_hash)
        add_api_data("tc", api_data, mapis_requests.request_threatcrowd(
            self.target_hash, "hash", dry_run=True), self.target_hash)
        add_api_data("otx", api_data, mapis_requests.request_alienvault_otx(
            self.target_hash, "hash", dry_run=True), self.target_hash)

        with redirect_stdout(StringIO()) as output:
            target_data = {
                "target": self.target_hash,
                "target_type": "hash",
                "target_api_data": api_data
            }
            print_target_data(target_data)
        
        with redirect_stdout(StringIO()) as vt_output:
            print_virustotal(api_data["vt"], self.target_hash, "hash")
        with redirect_stdout(StringIO()) as tc_output:
            print_threatcrowd(api_data["tc"], self.target_hash, "hash")
        with redirect_stdout(StringIO()) as otx_output:
            print_alienvault_otx(api_data["otx"], self.target_hash, "hash")

        expected = "".join((
            PrintTargetStrings.ANNOUNCE.format(target=self.target_hash) + "\n\n",
            vt_output.getvalue(),
            tc_output.getvalue(),
            otx_output.getvalue(),
            PrintTargetStrings.FINISH.format(target=self.target_hash) + "\n\n"
        ))

        self.assertEqual(output.getvalue(), expected)


    def test_print_target_address_empty(self):
        with redirect_stdout(StringIO()) as output:
            target_data = {
                "target": self.target_address,
                "target_type": "address",
                "target_api_data": dict()
            }
            print_target_data(target_data)
        
        expected = "\n".join((
            PrintTargetStrings.ANNOUNCE.format(target=self.target_address),
            "",
            PrintTargetStrings.EMPTY.format(target=self.target_address),
            PrintTargetStrings.ANNOUNCE.format(target=self.target_address),
            ""
        ))


    def test_print_target_hash_empty(self):
        with redirect_stdout(StringIO()) as output:
            target_data = {
                "target": self.target_hash,
                "target_type": "hash",
                "target_api_data": dict()
            }
            print_target_data(target_data)
        
        expected = "\n".join((
            PrintTargetStrings.ANNOUNCE.format(target=self.target_address),
            "",
            PrintTargetStrings.EMPTY.format(target=self.target_address),
            PrintTargetStrings.ANNOUNCE.format(target=self.target_address),
            ""
        ))
