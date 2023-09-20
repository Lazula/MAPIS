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

from mapis_data import *

class TestPrintStatus(unittest.TestCase):
    api = "test_api"
    target = "target_name"

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


    def test_print_status_success(self):
        self.assertEqual(
            status_string(True, self.api, self.target),
            Strings.SUCCESS.format(api=self.api, target=self.target)
        )


    def test_print_status_failure(self):
        self.assertEqual(
            status_string(False, self.api, self.target),
            Strings.FAIL.format(api=self.api, target=self.target)
        )
        self.assertEqual(
            status_string(False, self.api, self.target, status_code=400),
            Strings.FAIL_WITH_CODE.format(api=self.api, target=self.target, status_code=400)
        )
