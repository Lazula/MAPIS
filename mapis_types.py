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
import json
import socket
import sys

from copy import deepcopy
from dataclasses import dataclass, field

INTERACTIVE_COMMANDS = {
    "help": "Print this help prompt",
    "quit": "Exit the program",
    "warranty": "Show warranty information",
    "redistribution": "Show information about terms of redistribution",
    "screenshot": "Take screenshots for the previous target"
}


class TargetType(enum.IntEnum):
    Address = enum.auto()
    Hash = enum.auto()
    Command = enum.auto()


class API(enum.IntEnum):
    IPAPI = enum.auto()
    Shodan = enum.auto()
    VirusTotal = enum.auto()
    ThreatCrowd = enum.auto()
    AlienVault = enum.auto()

    @staticmethod
    def from_id(s: str):
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


    def __repr__(self):
        return APIS[self].id


    def __str__(self):
        return APIS[self].name


@dataclass(frozen=True)
class APIInfo:
    id: str
    name: str
    key_needed: bool
    target_types: tuple[TargetType]


    def __repr__(self):
        return self.id


    def __str__(self):
        return self.name


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

@dataclass
class Target:
    name: str
    type: TargetType
    data: dict[API, dict] = field(default_factory=dict)
    _type: str = "Target"

    @staticmethod
    def deduce_type(name: str) -> TargetType:
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


    def __serializable__(self):
        se = deepcopy(self.__dict__)
        se["type"] = se["type"].name
        se["data"] = {
            k.name: v
            for k, v in se["data"].items()
        }
        return se


    @staticmethod
    def __deserialize__(o: dict):
        de = deepcopy(o)
        de["type"] = TargetType[de["type"]]
        de["data"] = {
            API[k]: v
            for k, v in de["data"].items()
        }
        return Target(**de)


class UnsupportedTargetTypeError(ValueError):
    pass


class Encoder(json.JSONEncoder):
    def default(self, o):
        if hasattr(o, "__serializable__"):
            try:
                return o.__serializable__()
            except TypeError:
                return json.JSONEncoder.default(self, o)
        else:
            try:
                return o.__dict__
            except AttributeError:
                return json.JSONEncoder.default(self, o)


class Decoder(json.JSONDecoder):
    def __init__(self):
        super().__init__(object_hook=self.object_hook)


    def object_hook(self, o):
        # If the object doesn't have a _type flag, return it as a dict
        try:
            obj_type = o["_type"]
        except KeyError:
            return o

        # Try to convert the typename string to a class from mapis_types
        try:
            classtype = getattr(sys.modules["mapis_types"], obj_type)
        except AttributeError: # does not exist
            raise TypeError(f"No such _type {obj_type} in mapis_types")

        try:
            return getattr(sys.modules["mapis_types"], obj_type).__deserialize__(o)
        except AttributeError: # no __deserialize__
            raise TypeError(f"Given _type {obj_type} has no __deserialize__() staticmethod")
