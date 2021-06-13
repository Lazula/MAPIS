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
import time

from selenium import webdriver
from selenium.webdriver.firefox.options import Options


def create_headless_firefox_driver():
    options = Options()
    options.add_argument("--headless")

    driver = webdriver.Firefox(options=options)
    return driver


def screenshot_target(driver, target, target_type, folder, verbose=False, overwrite=False):
    if not os.path.exists(folder):
        os.makedirs(folder)

    if target_type == "address":
        screenshot_shodan(driver, target, target_type, folder, verbose=verbose, overwrite=overwrite)
    elif target_type == "hash":
        pass
    else:
        raise ValueError(f"Unsupported target type {target_type}")

    screenshot_virustotal(driver, target, target_type, folder, verbose=verbose, overwrite=overwrite)
    screenshot_threatcrowd(driver, target, target_type, folder, verbose=verbose, overwrite=overwrite)
    screenshot_alienvault_otx(driver, target, target_type, folder, verbose=verbose, overwrite=overwrite)


def screenshot_shodan(driver, target, target_type, folder, verbose=False, overwrite=False):
    if target_type == "address":
        screenshot_path = f"{folder}/shodan.png"
        exists = os.path.exists(screenshot_path)
        if (not exists) or (exists and overwrite):
            driver.set_window_size(1000, 2000)
            driver.get(f"https://www.shodan.io/host/{target}")
            driver.save_screenshot(screenshot_path)
        elif verbose:
            print(f"{screenshot_path} exists and overwrite is disabled. Skipping screenshot.")
    else:
        raise ValueError(f"Unsupported target type {target_type}")


def screenshot_virustotal(driver, target, target_type, folder, verbose=False, overwrite=False):
    detection_screenshot_path = f"{folder}/virustotal_detection.png"
    summary_screenshot_path = f"{folder}/virustotal_summary.png"

    if target_type == "address":
        exists = os.path.exists(detection_screenshot_path)
        if (not exists) or (exists and overwrite):
            driver.set_window_size(1000, 2350)
            driver.get(f"https://www.virustotal.com/gui/ip-address/{target}/detection")
            time.sleep(1)
            driver.save_screenshot(detection_screenshot_path)
        elif verbose:
            print(f"{detection_screenshot_path} exists and overwrite is disabled. Skipping screenshot.")

        exists = os.path.exists(detection_screenshot_path)
        if (not exists) or (exists and overwrite):
            driver.set_window_size(500, 750)
            driver.get(f"http://www.virustotal.com/gui/ip-address/{target}/summary")
            time.sleep(1)
            driver.save_screenshot(summary_screenshot_path)
        elif verbose:
            print(f"{screenshot_path} exists and overwrite is disabled. Skipping screenshot.")
    elif target_type == "hash":
        exists = os.path.exists(detection_screenshot_path)
        if (not exists) or (exists and overwrite):
            driver.set_window_size(1000, 2350)
            driver.get(f"http://www.virustotal.com/gui/file/{target}/detection")
            time.sleep(1)
            driver.save_screenshot(f"{folder}/virustotal_detection.png")
        elif verbose:
            print(f"{summary_screenshot_path} exists and overwrite is disabled. Skipping screenshot.")
    else:
        raise ValueError(f"Unsupported target type {target_type}")


def screenshot_threatcrowd(driver, target, target_type, folder, verbose=False, overwrite=False):
    screenshot_path = f"{folder}/threatcrowd.png"

    if target_type == "address":
        exists = os.path.exists(screenshot_path)
        if (not exists) or (exists and overwrite):
            driver.set_window_size(1800, 1700)
            driver.get(f"https://threatcrowd.org/ip.php?ip={target}")
            time.sleep(1)
            driver.save_screenshot(f"{folder}/threatcrowd.png")
        elif verbose:
            print(f"{screenshot_path} exists and overwrite is disabled. Skipping screenshot.")
    elif target_type == "hash":
        exists = os.path.exists(screenshot_path)
        if (not exists) or (exists and overwrite):
            driver.set_window_size(1800, 1700)
            driver.get(f"https://threatcrowd.org/pivot.php?data={target}")
            time.sleep(1)
            driver.save_screenshot(f"{folder}/threatcrowd.png")
        elif verbose:
            print(f"{screenshot_path} exists and overwrite is disabled. Skipping screenshot.")
    else:
        raise ValueError(f"Unsupported target type {target_type}")


def screenshot_alienvault_otx(driver, target, target_type, folder, verbose=False, overwrite=False):
    screenshot_path = f"{folder}/alienvault_otx.png"

    if target_type == "address":
        exists = os.path.exists(screenshot_path)
        if (not exists) or (exists and overwrite):
            driver.set_window_size(2000, 3000)
            driver.get(f"https://otx.alienvault.com/indicator/ip/{target}")
            time.sleep(3)
            driver.save_screenshot(f"{folder}/alienvault_otx.png")
        elif verbose:
            print(f"{screenshot_path} exists and overwrite is disabled. Skipping screenshot.")
    elif target_type == "hash":
        exists = os.path.exists(screenshot_path)
        if (not exists) or (exists and overwrite):
            driver.set_window_size(2000, 3000)
            driver.get(f"https://otx.alienvault.com/indicator/file/{target}")
            time.sleep(3)
            driver.save_screenshot(f"{folder}/alienvault_otx.png")
        elif verbose:
            print(f"{screenshot_path} exists and overwrite is disabled. Skipping screenshot.")
    else:
        raise ValueError(f"Unsupported target type {target_type}")
