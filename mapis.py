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
import sys
import argparse
from os.path import join

import colorama
import vt

import mapis_requests
import mapis_print
import mapis_io
import mapis_data
import mapis_screenshots
import mapis_cache
import mapis_license_notices

# Map internal API names to printable strings
SUPPORTED_APIS = {
    "ip_api": "IP-API",
    "shodan": "Shodan",
    "vt":     "VirusTotal",
    "tc":     "ThreatCrowd",
    "otx":    "AlienVault OTX",
    #"xforce": "XForce",
}

# Same as SUPPORTED_APIS, but only APIs that require keys
KEY_APIS = {
    "shodan": "Shodan",
    "vt":     "VirusTotal",
    #"xforce": "XForce",
}

# Appropriate target types for each API
API_TARGET_TYPES = {
    "ip_api": [ "address" ],
    "shodan": [ "address" ],
    "vt":     [ "address", "hash" ],
    "tc":     [ "address", "hash" ],
    "otx":    [ "address", "hash" ],
    #"xforce": [ "address", "hash" ],
}


def parse_arguments():
    parser = argparse.ArgumentParser(description="Query multiple API endpoints for information about IP addresses or hashes.")
    parser.add_argument("-c", "--color", action="store_true", help="Enable color output")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-a", "--api-list", type=str, help="List the APIs to use as a comma-separated list. Options: " + ", ".join(SUPPORTED_APIS.keys()), metavar="API[,API...]")

    target_args = parser.add_mutually_exclusive_group()
    target_args.add_argument("-n", "--stdin", action="store_true", help="Interactive mode. Behaves properly when stdin is a pipe.")
    target_args.add_argument("-t", "--target-list", type=str, help="Comma-separated list of targets.", metavar="TARGET[,TARGET...]")
    target_args.add_argument("-T", "--target-file", type=str, help="File containing IP addresses and/or hashes; one per line.", metavar="FILE")

    key_args = parser.add_argument_group(description="Key arguments.")
    key_args.add_argument("--keydir", type=str, help="Directory which stores API key files (name format: <api_name>_key.txt). Other key options will override these files.", default="API_KEYS")
    key_args.add_argument("--shodan-key", type=str, help="Shodan API key (overrides keyfile).")
    key_args.add_argument("--vt-key", type=str, help="VirusTotal API key (overrides keyfile).")
    #key_args.add_argument("--xforce-key", type=str, help="XForce API key (overrides keyfile).")

    # TODO time this
    screenshot_args = parser.add_argument_group(description="Screenshot arguments. Screenshots slow down lookups significantly - it is recommended to only use them after confirmation. Screenshots are not subject to quota limitations at this time.")
    screenshot_args.add_argument("-s", "--screenshot", action="store_true", help="Enable saving screenshots of web interfaces.")
    screenshot_args.add_argument("-f", "--screenshot-folder", type=str, help="Folder to store screenshots.", default="screenshots", metavar="FOLDER")
    screenshot_args.add_argument("--force-screenshot", action="store_true", help="Overwrite existing screenshots.")
    #TODO add args for naming conventions?
    #TODO option to categorize based on risk?
    #     filter by risk level and automaically
    #     screenshot on a hit?

    cache_args = parser.add_argument_group(description="Caching arguments.")
    cache_args.add_argument("--cache-folder", type=str, help="Specify a custom cache location. For faster performance without persistence, try using a ramdisk.", default="response_cache", metavar="FOLDER")
    cache_args.add_argument("--no-cache", action="store_true", help="Disable caching new responses to disk and loading cached responses from disk.")
    cache_args.add_argument("--disk-quota", action="store_true", help="Enable disk quota to limit space used by response caching. If not used, it is recommended to periodically clear the cache folder.")
    cache_args.add_argument("--disk-quota-size", type=str, help="Maximum disk usage in bytes or human-readable format. Supports base 10 and base 2 units, as well as decimal input. (e.g.: 1000, 50.5KB, 800MiB, 5G)", default="1GiB")
    cache_args.add_argument("--disk-quota-strategy", type=str, choices=["fifo", "keep"], help="Determine behavior when disk quota is reached. \"fifo\": Discard oldest cache entries. May cause increased disk wear with small quotas. \"keep\" (default): Stop caching new entries.", default="keep")

    debug_args = parser.add_argument_group(description="Debugging options.")
    debug_args.add_argument("--dry-run", action="store_true", help="Use dummy responses in place of real requests. Disables the screenshot option entirely.")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if not args.color:
        mapis_print.disable_color()

    if not os.path.isdir(args.keydir):
        args.keydir = None

    if args.api_list:
        args.api_list = args.api_list.split(",")
    else:
        args.api_list = SUPPORTED_APIS.keys()

    for api in args.api_list:
        if api not in SUPPORTED_APIS.keys():
            parser.print_help()
            print(f"\nInvalid API {api} provided in -a/--api-list.")
            raise RuntimeError

    if not args.keydir:
        for api, name in KEY_APIS.items():
            if api in args.api_list and not vars(args).get(f"{api}_key"):
                parser.print_help()
                print(f"\n{name} key missing.")
                print("You must specify an existing key directory if you have not provided all API keys.")
                raise RuntimeError

    if not (args.stdin or args.target_list or args.target_file):
        parser.print_help()
        print("\nNo targets specified.")
        raise RuntimeError

    if args.disk_quota and not mapis_cache.readable_to_bytes(args.disk_quota_size):
        print(f"\nFailed to parse \"{args.disk_quota_size}\" as a valid size.")
        raise RuntimeError

    if args.dry_run:
        if args.screenshot:
            args.screenshot = False
            print(f"{colorama.Fore.LIGHTRED_EX}{colorama.Style.BRIGHT}Dry run: screenshot option forcefully disabled.")

    return args


def read_keys(args):
    keys = dict()

    for api in KEY_APIS.keys():
        if api not in args.api_list:
            continue

        # First, check for keys given in arguments
        arg_key = vars(args).get(f"{api}_key")
        if arg_key:
            keys[api] = arg_key
        # Otherwise, try to read key from file
        elif args.keydir:
            try:
                keys[api] = open(join(args.keydir, f"{api}_key.txt")).read().strip()
            except OSError:
                # Skip over nonexistent keys silently
                # Missing key errors are handled outside this function
                pass

    return keys


def main():
    colorama.init(autoreset=True)

    try:
        args = parse_arguments()
    except RuntimeError:
        print("Error encountered during argument parsing.")
        return 1

    # Only one input method is allowed at once, so only one of these will run.
    if args.stdin:
        targets = mapis_io.read_targets_stdin()

    if args.target_list:
        targets = mapis_io.read_targets_list(args.target_list)

    if args.target_file:
        targets = mapis_io.read_targets_file(args.target_file)

    keys = read_keys(args)

    # This is NOT redundant with the argument checker.
    # Only this check accounts for missing key files.
    for api in KEY_APIS.keys():
        if api in args.api_list and api not in keys:
            print(f"No {api} key. Provide it with --{api}-key or in the key directory as {api}_key.txt")
            return 1

    driver = mapis_screenshots.create_headless_firefox_driver()

    # Disable caching if turned off in options or dry run
    cache_responses = not (args.no_cache or args.dry_run)
    if cache_responses:
        os.makedirs(args.cache_folder, exist_ok=True)

    quota_size = mapis_cache.readable_to_bytes(args.disk_quota_size)
    current_disk_usage = None

    vt_client = vt.Client(keys["vt"])
    previous_target = None
    previous_target_type = None

    for (target, target_type) in targets:
        if not target_type:
            print(f'Failed to parse "{target}" as IP address, hash, or command.')
            continue

        # Process commands
        if target_type == "command":
            if target == "help":
                for command, help_text in mapis_io.INTERACTIVE_COMMANDS.items():
                    print(command, ": ", help_text, sep="")
            elif target == "quit":
                break
            elif target == "warranty":
                print(mapis_license_notices.WARRANTY)
            elif target == "redistribution":
                print(mapis_license_notices.REDISTRIBUTION)
            elif target == "screenshot":
                if previous_target:
                    print("Taking screenshots for {previous_target_type}.")
                    target_screenshot_folder = join(args.screenshot_folder, previous_target_type, previous_target)
                    mapis_screenshots.screenshot_target(driver, previous_target, previous_target_type, target_screenshot_folder, verbose=args.verbose, overwrite=args.force_screenshot)
                else:
                    print("The `screenshot` command can only be used if a target has already been provided.")
            else:
                print(f"Invalid command {target} (should have been checked by read_targets_stdin)")

            print()
            # Following code applies only to lookups
            continue

        previous_target, previous_target_type = target, target_type

        print(f"{colorama.Style.BRIGHT}Looking up \"{target}\"...")
        print()

        if args.screenshot:
            # Format example: folder/address/1.2.3.4/virustotal.png
            target_screenshot_folder = join(args.screenshot_folder, target_type, target)
            mapis_screenshots.screenshot_target(driver, target, target_type, target_screenshot_folder, verbose=args.verbose, overwrite=args.force_screenshot)

        print()

        # Attempt to load from disk cache
        if cache_responses:
            target_data_dict = mapis_cache.get_cache_entry(args.cache_folder, target, verbose=args.verbose)
            if target_data_dict:
                mapis_print.print_target_data(target_data_dict)
                continue

        # Initialize data storage dict
        target_data_dict = {
            "target": target,
            "target_type": target_type,
            "target_api_data": dict()
        }

        # Make requests and record in target data
        for api, types in API_TARGET_TYPES.items():
            if api not in args.api_list:
                continue

            if target_type in types:
                response = mapis_requests.make_request(api, target, target_type, keys,
                        vt_client=vt_client, dry_run=args.dry_run)
                mapis_data.add_api_data(api, target_data_dict["target_api_data"], response, target)

        # Cache to disk
        if cache_responses:
            current_disk_usage = mapis_cache.put_cache_entry(args.cache_folder, target_data_dict,
                    use_quota=args.disk_quota, quota_size=quota_size,
                    quota_strategy=args.disk_quota_strategy, current_disk_usage=current_disk_usage,
                    verbose=args.verbose)

        # Print all found data
        mapis_print.print_target_data(target_data_dict)

    vt_client.close()

if __name__ == "__main__":
    main()
