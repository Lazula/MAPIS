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

import os
import tempfile
import unittest

from contextlib import redirect_stdout
from io import StringIO

from mapis_cache import *

class TestHumanReadableSize(unittest.TestCase):
    def test_readable_to_bytes(self):
        # No units means bytes
        self.assertEqual(readable_to_bytes("300"), 300)
        
        # Base 10
        self.assertEqual(readable_to_bytes("123KB"), 123 * 1000)
        self.assertEqual(readable_to_bytes("456M"), 456 * 1000**2)
        self.assertEqual(readable_to_bytes("789G"), 789 * 1000**3)
        self.assertEqual(readable_to_bytes("147T"), 147 * 1000**4)
        self.assertEqual(readable_to_bytes("1.5K"), 1.5 * 1000)

        # Base 2
        self.assertEqual(readable_to_bytes("123KiB"), 123 * 1024)
        self.assertEqual(readable_to_bytes("456Mi"), 456 * 1024**2)
        self.assertEqual(readable_to_bytes("789GiB"), 789 * 1024**3)
        self.assertEqual(readable_to_bytes("147ti"), 147 * 1024**4)
        self.assertEqual(readable_to_bytes("1.5Ki"), 1.5 * 1024)


    def test_bytes_to_readable(self):
        # Always base 2
        self.assertEqual(bytes_to_readable(123 * 1024), "123KiB")
        self.assertEqual(bytes_to_readable(456 * 1024**2), "456MiB")
        self.assertEqual(bytes_to_readable(789 * 1024**3), "789GiB")
        self.assertEqual(bytes_to_readable(147 * 1024**4), "147TiB")
        self.assertEqual(bytes_to_readable(1.5 * 1024), "1.5KiB")


class TestCache(unittest.TestCase):
    sample_data_address = {
        "target": Target("127.0.0.1", TargetType.Address),
        "target_api_data": {
            "api1": {
                "data1": "val1",
                "data2": "value2"
            }
        }
    }

    sample_data_hash = {
        "target": Target("0000", TargetType.Hash),
        "target_api_data": {
            "api3": {
                "a": 1,
                "b": 2
            },
            "api4": {
                "c": 3,
                "d": 4
            }
        }
    }

    def test_get_cache_usage(self):
        with tempfile.TemporaryDirectory() as cache_folder:
            fp1 = os.path.join(cache_folder, "1")
            fp2 = os.path.join(cache_folder, "2")

            with open(fp1, "w") as f:
                f.write("A"*500)
            
            with open(fp2, "w") as f:
                f.write("B"*2000)
            
            fs1 = os.path.getsize(fp1)
            fs2 = os.path.getsize(fp2)

            self.assertEqual(get_cache_usage(cache_folder), fs1+fs2)


    def test_get_cache_filename(self):
        self.assertEqual(
            get_cache_filename(self.sample_data_address),
            f"{self.sample_data_address['target']}.cache.json"
        )
        self.assertEqual(
            get_cache_filename(self.sample_data_hash),
            f"{self.sample_data_hash['target']}.cache.json"
        )
        self.assertRaises(
            KeyError,
            get_cache_filename,
            {}
        )

    def test_cache_malformed_json(self):
        with tempfile.TemporaryDirectory() as cache_folder:
            malformed_path = os.path.join(cache_folder, "malformed.cache.json")
            with open(malformed_path, "w") as f:
                f.write("malformed")
            with redirect_stdout(StringIO()) as output:
                result = get_cache_entry(cache_folder, "malformed", verbose=True)
                self.assertIsNone(result)
            self.assertEqual(output.getvalue(), f"Failed to load malformed from cache due to malformed JSON.\n")
            clear_cache_filelist()


    def test_cache_no_quota(self):
        with tempfile.TemporaryDirectory() as cache_folder:
            with redirect_stdout(StringIO()) as output:
                put_cache_entry(cache_folder, self.sample_data_address,
                                verbose=True)
            self.assertEqual(output.getvalue(), f"Wrote {self.sample_data_address['target']} to cache - Disk quota not enabled.\n")

            with redirect_stdout(StringIO()) as output:
                result = get_cache_entry(cache_folder, self.sample_data_address["target"],
                                         verbose=True)
            self.assertEqual(output.getvalue(), f"Found cache hit for {self.sample_data_address['target']}.\n")

            self.assertEqual(result, self.sample_data_address)

            with redirect_stdout(StringIO()) as output:
                put_cache_entry(cache_folder, self.sample_data_hash,
                                verbose=True)
            self.assertEqual(output.getvalue(), f"Wrote {self.sample_data_hash['target']} to cache - Disk quota not enabled.\n")

            with redirect_stdout(StringIO()) as output:
                result = get_cache_entry(cache_folder, self.sample_data_hash["target"],
                                         verbose=True)
                
            self.assertEqual(output.getvalue(), f"Found cache hit for {self.sample_data_hash['target']}.\n")

            self.assertEqual(result, self.sample_data_hash)
            clear_cache_filelist()


    def test_cache_quota_with_space(self):
        with tempfile.TemporaryDirectory() as cache_folder:
            quota_opts = {
                "use_quota": True,
                "quota_size": readable_to_bytes("1Ki"),
                "quota_strategy": "fifo"
            }

            with redirect_stdout(StringIO()) as output:
                put_cache_entry(cache_folder, self.sample_data_address, **quota_opts,
                                verbose=True)
            self.assertEqual(
                output.getvalue(),
                "\n".join((
                    f"Wrote {self.sample_data_address['target']} to cache - Sufficient space.",
                    "Disk quota usage at 116B of 1KiB (116 of 1024 bytes)",
                    ""
                ))
            )

            with redirect_stdout(StringIO()) as output:
                result = get_cache_entry(cache_folder, self.sample_data_address["target"],
                                         verbose=True)
            self.assertEqual(
                output.getvalue(),
                "\n".join((
                    f"Found cache hit for {self.sample_data_address['target']}.",
                    ""
                ))
            )

            self.assertEqual(result, self.sample_data_address)

            with redirect_stdout(StringIO()) as output:
                put_cache_entry(cache_folder, self.sample_data_hash, **quota_opts,
                                verbose=True)
            self.assertEqual(
                output.getvalue(),
                "\n".join((
                    f"Wrote {self.sample_data_hash['target']} to cache - Sufficient space.",
                    "Disk quota usage at 230B of 1KiB (230 of 1024 bytes)",
                    ""
                ))
            )

            with redirect_stdout(StringIO()) as output:
                result = get_cache_entry(cache_folder, self.sample_data_hash["target"],
                                         verbose=True)
            self.assertEqual(
                output.getvalue(),
                "\n".join((
                    f"Found cache hit for {self.sample_data_hash['target']}.",
                    ""
                ))
            )

            self.assertEqual(result, self.sample_data_hash)
            clear_cache_filelist()


    def test_cache_quota_no_space_fifo(self):
        with tempfile.TemporaryDirectory() as cache_folder:
            clear_cache_filelist()
            address_dump_size = len(json.dumps(self.sample_data_address))
            hash_dump_size = len(json.dumps(self.sample_data_hash))

            spacetaker_path = os.path.join(cache_folder, "spacetaker")
            with open(spacetaker_path, "w") as f:
                spacetaker_size = f.write("A"*5000)

            quota_opts = {
                "use_quota": True,
                "quota_strategy": "fifo"
            }

            # Cache contains only the arbitrary file
            current_disk_usage = get_cache_usage(cache_folder)
            self.assertEqual(current_disk_usage, spacetaker_size)

            expected_contents = set(["spacetaker"])
            self.assertEqual(set(os.listdir(cache_folder)), expected_contents)


            # Set the quota size to the size of the next file
            # to force replacement
            quota_opts["quota_size"] = address_dump_size

            # Cache now contains only the address dump
            with redirect_stdout(StringIO()) as output:
                new_disk_usage = put_cache_entry(cache_folder, self.sample_data_address, **quota_opts,
                                                 verbose=True)
            self.assertEqual(
                output.getvalue(),
                "\n".join((
                    f"Deleting {spacetaker_path} according to fifo disk cache strategy. ({bytes_to_readable(spacetaker_size)} cleared)",
                    f"Wrote {self.sample_data_address['target']} to cache - Cleared space.",
                    "Disk quota usage at 116B of 116B (116 of 116 bytes)",
                    ""
                ))
            )

            self.assertEqual(new_disk_usage, address_dump_size)

            expected_contents = set([get_cache_filename(self.sample_data_address)])
            self.assertEqual(set(os.listdir(cache_folder)), expected_contents)

            with redirect_stdout(StringIO()) as output:
                result = get_cache_entry(cache_folder, self.sample_data_address["target"],
                                         verbose=True)
            self.assertEqual(
                output.getvalue(),
                "\n".join((
                    f"Found cache hit for {self.sample_data_address['target']}.",
                    ""
                ))
            )

            self.assertEqual(result, self.sample_data_address)


            # Force replacement again
            quota_opts["quota_size"] = hash_dump_size

            with redirect_stdout(StringIO()) as output:
                new_disk_usage = put_cache_entry(cache_folder, self.sample_data_hash, **quota_opts,
                                                 verbose=True)
            self.assertEqual(
                output.getvalue(),
                "\n".join((
                    f"Deleting {get_cache_filename(self.sample_data_address)} according to fifo disk cache strategy. ({bytes_to_readable(address_dump_size)} cleared)",
                    f"Wrote {self.sample_data_hash['target']} to cache - Cleared space.",
                    "Disk quota usage at 114B of 114B (114 of 114 bytes)",
                    ""
                ))
            )

            self.assertEqual(new_disk_usage, hash_dump_size)

            expected_contents = set([get_cache_filename(self.sample_data_hash)])
            self.assertEqual(set(os.listdir(cache_folder)), expected_contents)

            with redirect_stdout(StringIO()) as output:
                result = get_cache_entry(cache_folder, self.sample_data_hash["target"],
                                         verbose=True)
            self.assertEqual(
                output.getvalue(),
                "\n".join((
                    f"Found cache hit for {self.sample_data_hash['target']}.",
                    ""
                ))
            )

            self.assertEqual(result, self.sample_data_hash)
            clear_cache_filelist()


    def test_cache_quota_no_space_keep(self):
        with tempfile.TemporaryDirectory() as cache_folder:
            with open(os.path.join(cache_folder, "spacetaker"), "w") as f:
                spacetaker_size = f.write("A"*(1024*4))

            quota_opts = {
                "use_quota": True,
                "quota_size": spacetaker_size,
                "quota_strategy": "keep"
            }

            # Cache contains only the arbitrary file
            current_disk_usage = get_cache_usage(cache_folder)
            self.assertEqual(current_disk_usage, spacetaker_size)

            expected_contents = set(["spacetaker"])
            self.assertEqual(set(os.listdir(cache_folder)), expected_contents)

            with redirect_stdout(StringIO()) as output:
                new_disk_usage = put_cache_entry(cache_folder, self.sample_data_address, **quota_opts,
                                                 verbose=True)
            self.assertEqual(
                output.getvalue(),
                "\n".join((
                    f"Did not write {self.sample_data_address['target']} to cache - Not enough space.",
                    "Disk quota usage at 4KiB of 4KiB (4096 of 4096 bytes)",
                    ""
                ))
            )

            self.assertEqual(new_disk_usage, spacetaker_size)

            expected_contents = set(["spacetaker"])
            self.assertEqual(set(os.listdir(cache_folder)), expected_contents)

            with redirect_stdout(StringIO()) as output:
                result = get_cache_entry(cache_folder, self.sample_data_address["target"],
                                         verbose=True)
            self.assertEqual(
                output.getvalue(),
                "\n".join((
                    f"Failed to find {self.sample_data_address['target']} in cache.",
                    ""
                ))
            )

            self.assertIsNone(result)

            with redirect_stdout(StringIO()) as output:
                new_disk_usage = put_cache_entry(cache_folder, self.sample_data_hash, **quota_opts,
                                                 verbose=True)
            self.assertEqual(
                output.getvalue(),
                "\n".join((
                    f"Did not write {self.sample_data_hash['target']} to cache - Not enough space.",
                    "Disk quota usage at 4KiB of 4KiB (4096 of 4096 bytes)",
                    ""
                ))
            )

            self.assertEqual(new_disk_usage, spacetaker_size)

            expected_contents = set(["spacetaker"])
            self.assertEqual(set(os.listdir(cache_folder)), expected_contents)

            with redirect_stdout(StringIO()) as output:
                result = get_cache_entry(cache_folder, self.sample_data_hash["target"],
                                         verbose=True)
            self.assertEqual(
                output.getvalue(),
                "\n".join((
                    f"Failed to find {self.sample_data_hash['target']} in cache.",
                    ""
                ))
            )

            self.assertIsNone(result)
            clear_cache_filelist()
