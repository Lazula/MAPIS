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

import os
import json

from os.path import join

cache_files_by_age = list()

readable_size_units = {
    "": 1,  "K":   1000, "M":  1000**2, "G":  1000**3, "T":  1000**4,
            "Ki":  1024, "Mi": 1024**2, "Gi": 1024**3, "Ti": 1024**4,

    "B": 1, "KB":  1000, "MB":  1000**2, "GB":  1000**3, "TB":  1000**4,
            "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3, "TiB": 1024**4
}

def readable_to_bytes(size_str):
    try:
        return int(size_str)
    except ValueError:
        pass

    try:
        # Use descending order to not catch "B" first
        for letter in "TGMKB":
            units_index = size_str.find(letter)
            if units_index > -1:
                break

        number = size_str[:units_index].strip()
        unit = size_str[units_index:].strip()
        return int(float(number) * readable_size_units[unit])
    except ValueError as err:
        print(repr(err))
        return None


def bytes_to_readable(size_bytes):
    size_bytes = int(size_bytes)
    binary_units = ("B", "KiB", "MiB", "GiB", "TiB")
    i = 0
    while size_bytes >= 1024 and i < len(binary_units):
        size_bytes /= 1024
        i += 1
    return f"{size_bytes:.2f}".rstrip("0") + binary_units[i]


def get_cache_entry(cache_folder, target, verbose=False):
    try:
        cache_file_name = ".".join([target, "cache.json"])
        cache_file_path = join(cache_folder, cache_file_name)
        with open(cache_file_path) as cache_file:
            target_data_dict = json.load(cache_file)
        if verbose:
            print(f"Found cache hit for {target}")
        return target_data_dict
    except FileNotFoundError:
        if verbose:
            print(f"Failed to find {target} in cache")
    except json.JSONDecodeError:
        if verbose:
            print(f"Failed to load {target} from cache due to malformed JSON.")
    except Exception as err:
        if verbose:
            print(f"Unexpected error while getting cache entry:\n{repr(err)}")
    return


def put_cache_entry(cache_folder, target_data_dict, use_quota=False, quota_size=None, quota_strategy=None, current_disk_usage=None, verbose=False):
    target = target_data_dict["target"]
    cache_file_name = ".".join([target, "cache.json"])
    cache_file_path = join(cache_folder, cache_file_name)
    cache_data = json.dumps(target_data_dict)

    write_to_cache = False
    reason = None

    if not current_disk_usage:
        current_disk_usage = os.path.getsize(cache_folder)

    if use_quota:
        # Initialize age listing if not done yet
        # (lazily put off until needed)
        if not cache_files_by_age:
            # Sort by age - oldest first, newest last
            cache_files_by_age.extend(sorted([join(cache_folder, item) for item in os.listdir(cache_folder)], key=os.path.getctime))
        if current_disk_usage is None:
            current_disk_usage = os.path.getsize(cache_folder)


    # Disk quota enabled AND larger than quota
    if use_quota and len(cache_data) > quota_size:
        write_to_cache = False
        reason = "Cache entry size exceeds quota size."
    # Disk quota enabled AND won't exceed quota
    elif use_quota and current_disk_usage + len(cache_data) <= quota_size:
        write_to_cache = True
        reason = "Sufficient space."
    # Disk quota enabled AND will exceed quota
    elif quota_size:
        # Handle quota strategy
        if quota_strategy == "fifo":
            # Clear oldest entries until we have enough free space
            while current_disk_usage + len(cache_data) > quota_size:
                oldest_path = cache_files_by_age[0]
                oldest_path_size = os.path.getsize(oldest_path)
                if verbose:
                    print(f"Deleting {oldest_path} according to fifo disk cache strategy.",
                          f"({bytes_to_readable(oldest_path_size)} cleared)")
                # Delete the oldest entry from the disk...
                os.unlink(oldest_path)
                # ... reduce the tracked disk usage...
                current_disk_usage -= oldest_path_size
                # ... and finally, remove it from the tracker.
                del cache_files_by_age[0]

            write_to_cache = True
            reason = "Cleared space."
        elif quota_strategy == "keep":
            if current_disk_usage + len(cache_data) <= quota_size:
                write_to_cache = True
                reason = None
        else:
            raise ValueError(f"use_quota set but no quota_strategy given.")
    # Disk quota disabled
    elif verbose:
        write_to_cache = True
        reason = "Disk quota not enabled."

    if write_to_cache:
        with open(cache_file_path, "w") as cache_file:
            cache_file.write(cache_data)
        cache_files_by_age.append(cache_file_name)
        current_disk_usage += os.path.getsize(cache_file_path)

    if verbose:
        print(f"Wrote {target} to cache" if write_to_cache else f"Did not write {target} to cache",
              f"- {reason}." if reason else ".")
        print(f"Disk quota usage at {bytes_to_readable(current_disk_usage)} of {bytes_to_readable(quota_size)}",
              f"({current_disk_usage} of {quota_size} bytes)")

    return current_disk_usage
