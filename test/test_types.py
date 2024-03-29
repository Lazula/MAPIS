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

from mapis_types import *


class TestTarget(unittest.TestCase):
    targets = (
        Target("127.0.0.1", TargetType.Address),
        Target("10.0.0.1", TargetType.Address),
        Target("172.16.0.1", TargetType.Address),
        Target("192.168.0.1", TargetType.Address),
        Target("0000", TargetType.Hash),
        Target("1111", TargetType.Hash),
        Target("2222", TargetType.Hash),
        Target("3333", TargetType.Hash),
        Target("invalid", None),
        Target("help", TargetType.Command)
    )

    def test_target_deduce_type(self):
        for target in self.targets:
            self.assertEqual(Target.deduce_type(target.name), target.type)


class TestUnsupportedTargetTypeError(unittest.TestCase):
    def test_unsupported_target_type_error(self):
        def raiser(target_type: TargetType):
            if target_type is not TargetType.Address:
                raise UnsupportedTargetTypeError(target_type)
            return True
        self.assertTrue(raiser(TargetType.Address))
        self.assertRaises(
            UnsupportedTargetTypeError,
            raiser,
            TargetType.Hash
        )
        self.assertRaises(
            UnsupportedTargetTypeError,
            raiser,
            TargetType.Command
        )
        self.assertRaises(
            UnsupportedTargetTypeError,
            raiser,
            None
        )


class TestJSONEncDec(unittest.TestCase):
    expected_encoded = "\n".join((
        '{',
        '    "name": "127.0.0.1",',
        '    "type": "Address",',
        '    "data": {',
        '        "IPAPI": {',
        '            "key1": "val1",',
        '            "key2": "val2"',
        '        },',
        '        "Shodan": {',
        '            "key3": "val3",',
        '            "key4": "val4"',
        '        }',
        '    },',
        '    "_type": "Target"',
        '}'
    ))

    expected_decoded = Target(
        name = "127.0.0.1",
        type = TargetType.Address,
        data = {
            API.IPAPI: {
                "key1": "val1",
                "key2": "val2"
            },
            API.Shodan: {
                "key3": "val3",
                "key4": "val4"
            }
        }
    )

    def test_encoder(self):
        encoded = json.dumps(self.expected_decoded, cls=Encoder, indent=4)
        self.assertEqual(self.expected_encoded, encoded)


    def test_decoder(self):
        decoded = json.loads(self.expected_encoded, cls=Decoder)
        self.assertIsInstance(decoded, Target)
        self.assertEqual(self.expected_decoded, decoded)


    def test_unsupported_object(self):
        class NotSupported:
            pass

        self.assertRaises(
            TypeError,
            json.dumps,
            NotSupported(),
            cls=Decoder
        )
