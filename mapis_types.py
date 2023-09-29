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

import enum
import socket

from dataclasses import dataclass

INTERACTIVE_COMMANDS = {
    "help": "Print this help prompt",
    "quit": "Exit the program",
    "warranty": "Show warranty information",
    "redistribution": "Show information about terms of redistribution",
    "screenshot": "Take screenshots for the previous target"
}

class API(enum.Enum):
    IPAPI = enum.auto()
    Shodan = enum.auto()
    VirusTotal = enum.auto()
    ThreatCrowd = enum.auto()
    AlienVault = enum.auto()

    @classmethod
    def from_id(self, s: str):
        try:
            return {
                "ip_api": API.IPAPI,
                "shodan": API.Shodan,
                "vt": API.VirusTotal,
                "tc": API.ThreatCrowd,
                "otx": API.AlienVault
            }[s]
        except KeyError:
            raise ValueError(s)


@dataclass(frozen=True)
class APIInfo:
    id: str
    name: str
    key_needed: bool
    target_types: tuple[TargetType]


APIS: dict[API, APIInfo] = {
    API.IPAPI: APIInfo("ip_api", "IP-API", False, (TargetType.Address,)),
    API.Shodan: APIInfo("shodan", "Shodan", True, (TargetType.Address,)),
    API.VirusTotal: APIInfo("vt", "VirusTotal", True, (TargetType.Address, TargetType.Hash,)),
    API.ThreatCrowd: APIInfo("tc", "ThreatCrowd", False, (TargetType.Address, TargetType.Hash,)),
    API.AlienVault: APIInfo("otx", "AlienVault OTX", False, (TargetType.Address, TargetType.Hash,))
}

# APIS but only for those with key_needed
KEY_APIS: dict[API, APIInfo] = {
    api: info
        for api, info in APIS.items()
        if info.key_needed
}


class TargetType(enum.Enum):
    Address = enum.auto()
    Hash = enum.auto()
    Command = enum.auto()


@dataclass
class Target:
    name: str
    type: TargetType

    @classmethod
    def deduce_type(self, name: str) -> TargetType:
        if name in INTERACTIVE_COMMANDS.keys():
            return TargetType.Command

        try:
            socket.inet_pton(socket.AF_INET, name)
            return TargetType.Address
        except socket.error:
            pass

        if all(c in "0123456789abcdefABCDEF" for c in name):
            return TargetType.Hash

        # No matching target type
        return None


    def __str__(self) -> str:
        return self.name


class UnsupportedTargetTypeError(ValueError):
    pass
