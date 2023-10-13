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

import json
import os
import sys

from os.path import join as pathjoin
from typing import Any

from mapis_types import *

cache_files_by_age: list[str] = list()

readable_size_units: dict[str, int] = {
    "":  1, "k":   1000, "m":   1000**2, "g":   1000**3, "t":   1000**4,
    "b": 1, "kb":  1000, "mb":  1000**2, "gb":  1000**3, "tb":  1000**4,

            "ki":  1024, "mi":  1024**2, "gi":  1024**3, "ti":  1024**4,
            "kib": 1024, "mib": 1024**2, "gib": 1024**3, "tib": 1024**4
}

def readable_to_bytes(hr_size: str) -> int:
    try:
        return int(hr_size)
    except ValueError:
        pass

    hr_size = hr_size.lower()

    try:
        # Use descending order to not catch "b" first
        for letter in "tgmkb":
            units_index = hr_size.find(letter)
            if units_index > -1:
                break

        number = hr_size[:units_index].strip()
        unit = hr_size[units_index:].strip()
        return int(float(number) * readable_size_units[unit])
    except ValueError as err:
        print(repr(err))
        return None


def bytes_to_readable(size_bytes: int) -> str:
    size_bytes = int(size_bytes)
    binary_units = ("B", "KiB", "MiB", "GiB", "TiB")
    i = 0
    while size_bytes >= 1024 and i < len(binary_units):
        size_bytes /= 1024
        i += 1
    return f"{size_bytes:.2f}".rstrip("0").rstrip(".") + binary_units[i]


def get_cache_filename(target_data_dict: dict[str, Any]) -> str:
    return f"{target_data_dict['target']}.cache.json"


def get_cache_usage(cache_folder: str) -> int:
    return sum(
        de.stat().st_size
        for de in os.scandir(cache_folder)
        if de.is_file()
    )


def clear_cache_filelist() -> None:
    global cache_files_by_age
    cache_files_by_age = list()


def get_cache_entry(cache_folder: str, target: Target, api_list: list[str] = None, verbose: bool = False) -> dict[str, dict]:
    try:
        cache_file_path = pathjoin(cache_folder, f"{target}.cache.json")
        with open(cache_file_path) as cache_file:
            target_data_dict = json.load(cache_file, cls=Decoder)
        if verbose:
            print(f"Found cache hit for {target}.")

        if api_list is not None:
            # list() is needed to avoid an error from changing the dict while
            # looping through it
            for api in list(target_data_dict["target_api_data"].keys()):
                if api not in api_list:
                    del target_data_dict["target_api_data"][api]

        return target_data_dict
    except FileNotFoundError:
        if verbose:
            print(f"Failed to find {target} in cache.")
    except json.JSONDecodeError:
        if verbose:
            print(f"Failed to load {target} from cache due to malformed JSON.")
    except Exception as err:
        if verbose:
            print(f"Unexpected error while getting cache entry:\n{repr(err)}")
    return


def put_cache_entry(cache_folder: str, target_data_dict: dict[str, dict], use_quota: bool = False, quota_size: bool = None, quota_strategy: bool = None, current_disk_usage: int = None, verbose: bool = False) -> int:
    """Add a target's data to the on-disk cache. Returns the new disk usage in bytes."""

    global cache_files_by_age
    target: Target = target_data_dict["target"]
    cache_file_name = f"{target}.cache.json"
    cache_file_path = pathjoin(cache_folder, cache_file_name)
    cache_data = json.dumps(target_data_dict, cls=Encoder)

    write_to_cache = True
    # TODO: use an enum
    reason = None

    if current_disk_usage is None:
        current_disk_usage = get_cache_usage(cache_folder)

    if use_quota:
        # Initialize age listing if not done yet
        # (lazily put off until needed)
        if len(cache_files_by_age) == 0:
            # Sort by age - oldest first, newest last
            cache_files_by_age.extend(
                sorted(
                    (
                        pathjoin(cache_folder, item)
                        for item in os.listdir(cache_folder)
                    ),
                    key=os.path.getctime
                )
            )
        if current_disk_usage is None:
            current_disk_usage = get_cache_usage(cache_folder)


    # Disk quota enabled AND larger than quota
    if use_quota and len(cache_data) > quota_size:
        write_to_cache = False
        reason = "Cache entry size exceeds quota size"
    # Disk quota enabled AND won't exceed quota
    elif use_quota and current_disk_usage + len(cache_data) <= quota_size:
        write_to_cache = True
        reason = "Sufficient space"
    # Disk quota enabled AND will exceed quota
    elif quota_size:
        # Handle quota strategy
        if quota_strategy == "fifo":
            # Clear oldest entries until we have enough free space
            while current_disk_usage + len(cache_data) > quota_size and len(cache_files_by_age) > 0:
                oldest_filename = cache_files_by_age[0]
                oldest_path = pathjoin(cache_folder, oldest_filename)
                oldest_path_size = os.path.getsize(oldest_path)
                if verbose:
                    print(f"Deleting {oldest_filename} according to fifo disk cache strategy.",
                          f"({bytes_to_readable(oldest_path_size)} cleared)")
                # Delete the oldest entry from the disk...
                os.unlink(oldest_path)
                # ... reduce the tracked disk usage...
                current_disk_usage -= oldest_path_size
                # ... and finally, remove it from the tracker.
                del cache_files_by_age[0]

            write_to_cache = True
            reason = "Cleared space"
        elif quota_strategy == "keep":
            if current_disk_usage + len(cache_data) > quota_size:
                write_to_cache = False
                reason = "Not enough space"
        else:
            raise ValueError(f"use_quota set but no quota_strategy given.")
    # Disk quota disabled
    elif verbose:
        write_to_cache = True
        reason = "Disk quota not enabled"

    if write_to_cache:
        with open(cache_file_path, "w") as cache_file:
            cache_file.write(cache_data)
        cache_files_by_age.append(cache_file_name)
        current_disk_usage += os.path.getsize(cache_file_path)

    if verbose:
        print(f"Wrote {target} to cache" if write_to_cache else f"Did not write {target} to cache",
              f"- {reason}."
              if reason
              else ".")
        if use_quota:
            print(f"Disk quota usage at {bytes_to_readable(current_disk_usage)} of {bytes_to_readable(quota_size)}",
                f"({current_disk_usage} of {quota_size} bytes)")

    return current_disk_usage
