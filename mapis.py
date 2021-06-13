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

import colorama
import vt

import mapis_requests
import mapis_print
import mapis_io
import mapis_data
import mapis_screenshots
import mapis_cache

def parse_arguments():
    parser = argparse.ArgumentParser(description="Query multiple API endpoints for information about IP addresses or hashes.")
    parser.add_argument("-c", "--color", action="store_true", help="Enable color output")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    target_args = parser.add_argument_group(description="Target arguments. These handle both IP addresses and hashes at the same time.")
    target_args.add_argument("-n", "--stdin", action="store_true", help="Interactive mode. Behaves when stdin in a pipe.")
    target_args.add_argument("-t", "--target-list", type=str, help="Comma-separated list of targets.", metavar="TARGET[,TARGET...]")
    target_args.add_argument("-T", "--target-file", type=str, help="File containing IP addresses and/or hashes; one per line.", metavar="FILE")

    key_args = parser.add_argument_group(description="Key arguments.")
    key_args.add_argument("--keydir", type=str, help="Directory which stores API key files.", default="API_KEYS")
    key_args.add_argument("--shodan-key", type=str, help="Shodan API key (overrides keyfile).")
    key_args.add_argument("--vt-key", type=str, help="VirusTotal API key (overrides keyfile).")
    #key_args.add_argument("--otx-key", type=str, help="OTX API key (overrides keyfile).")
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

    if not args.keydir and not (args.shodan_key and args.vt_key):
        parser.print_help()
        print("\nYou must specify either an existing key directory or all api keys.")
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


def main():
    colorama.init(autoreset=True)

    try:
        args = parse_arguments()
    except RuntimeError:
        print("Error encountered during argument parsing.")
        return 1

    if args.stdin:
        targets = mapis_io.read_targets_stdin()

    if args.target_list:
        targets = mapis_io.read_targets_list(args.target_list)

    if args.target_file:
        targets = mapis_io.read_targets_file(args.target_file)

    shodan_api_key = None
    vt_api_key = None
    #otx_api_key = None
    #xforce_api_key = None

    if args.keydir:
        try:
            shodan_api_key = open(f"{args.keydir}/shodanapikey.txt", "r").read().strip()
        except:
            pass
        try:
            vt_api_key = open(f"{args.keydir}/vtapikey.txt", "r").read().strip()
        except:
            pass
        #try:
        #    otx_api_key = open(f"{args.keydir}/otxapikey.txt", "r").read().strip()
        #except:
        #    pass
        #try:
        #    xforce_api_key = open(f"{args.keydir}/xforceapikey.txt", "r").read().strip()
        #except:
        #    pass

    if args.shodan_key:
        shodan_api_key = args.shodan_key
    if args.vt_key:
        vt_api_key = args.vt_key
    #if args.otx_key:
    #    otx_api_key = args.otx_key
    #if args.xforce_key:
    #    xforce_api_key = args.xforce_key

    if not shodan_api_key:
        raise RuntimeError("No Shodan key")
    if not vt_api_key:
        raise RuntimeError("No VT key")
    #if not otx_api_key:
    #    raise RuntimeError("No OTX key")
    #if not xforce_api_key
    #    raise RuntimeError("No XForce key")

    if args.screenshot:
        driver = mapis_screenshots.create_headless_firefox_driver()

        if not os.path.exists(args.screenshot_folder):
            os.mkdir(args.screenshot_folder)

    cache_responses = not args.no_cache and not args.dry_run

    if cache_responses and not os.path.exists(args.cache_folder):
        os.mkdir(args.cache_folder)

    quota_size = mapis_cache.readable_to_bytes(args.disk_quota_size)
    current_disk_usage = None

    vt_client = vt.Client(vt_api_key)

    for (target, target_type) in targets:
        if not target_type:
            print(f'Failed to parse "{target}" as IP address or hash.')
            continue

        print(f"{colorama.Style.BRIGHT}Looking up \"{target}\"...")
        print()

        if args.screenshot:
            # Format example: folder/address/1.2.3.4/virustotal.png
            target_screenshot_folder = f"{args.screenshot_folder}/{target_type}/{target}"
            mapis_screenshots.screenshot_target(driver, target, target_type, target_screenshot_folder, verbose=args.verbose, overwrite=args.force_screenshot)

        print()

        if args.screenshot:
            # Format example: folder/address/1.2.3.4/virustotal.png
            target_screenshot_folder = f"{args.screenshot_folder}/{target_type}/{target}"
            mapis_screenshots.screenshot_target(driver, target, target_type, target_screenshot_folder)

        # Initialize data storage dict
        target_data_dict = {
            "target": target,
            "target_type": target_type,
            "target_api_data": {}
        }

        if args.screenshot:
            # Format example: folder/address/1.2.3.4/virustotal.png
            target_screenshot_folder = f"{args.screenshot_folder}/{target_type}/{target}"
            mapis_screenshots.screenshot_target(driver, target, target_type, target_screenshot_folder)

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
            "target_api_data": {}
        }

        if target_type == "address":
            ip_api_response = mapis_requests.request_ip_api(target, target_type, dry_run=args.dry_run)
            mapis_data.add_ip_api_data(target_data_dict["target_api_data"], ip_api_response, target)

        if target_type == "address":
            shodan_response = mapis_requests.request_shodan(target, target_type, shodan_api_key, dry_run=args.dry_run)
            mapis_data.add_shodan_data(target_data_dict["target_api_data"], shodan_response, target)

        virustotal_response = mapis_requests.request_virustotal(vt_client, target, target_type, dry_run=args.dry_run)
        mapis_data.add_virustotal_data(target_data_dict["target_api_data"], virustotal_response, target)

        threatcrowd_response = mapis_requests.request_threatcrowd(target, target_type, dry_run=args.dry_run)
        mapis_data.add_threatcrowd_data(target_data_dict["target_api_data"], threatcrowd_response, target)

        alienvault_otx_response = mapis_requests.request_alienvault_otx(target, target_type, dry_run=args.dry_run)
        mapis_data.add_alienvault_otx_data(target_data_dict["target_api_data"], alienvault_otx_response, target, target_type)

        # Cache to disk
        if cache_responses:
            current_disk_usage = mapis_cache.put_cache_entry(args.cache_folder, target_data_dict, use_quota=args.disk_quota, quota_size=quota_size,
                                                     quota_strategy=args.disk_quota_strategy, current_disk_usage=current_disk_usage,
                                                     verbose=args.verbose)

        # Print all found data
        mapis_print.print_target_data(target_data_dict)

    vt_client.close()

if __name__ == "__main__":
    main()
