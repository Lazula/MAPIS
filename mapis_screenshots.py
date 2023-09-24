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

from os.path import join
from selenium import webdriver
from selenium.webdriver.firefox.options import Options

from mapis_types import *

def create_headless_firefox_driver() -> webdriver.Firefox:
    options = Options()
    options.add_argument("--headless")

    driver = webdriver.Firefox(options=options)
    return driver


def screenshot_target(driver: webdriver.Firefox, target: Target, folder: str, verbose: bool = False, overwrite: bool = False) -> None:
    os.makedirs(folder, exist_ok=True)

    if target.type == TargetType.Address:
        screenshot_shodan(driver, target, folder, verbose=verbose, overwrite=overwrite)
    elif target.type == TargetType.Hash:
        pass
    else:
        raise UnsupportedTargetTypeError(target.type)

    screenshot_virustotal(driver, target, folder, verbose=verbose, overwrite=overwrite)
    screenshot_threatcrowd(driver, target, folder, verbose=verbose, overwrite=overwrite)
    screenshot_alienvault_otx(driver, target, folder, verbose=verbose, overwrite=overwrite)


def take_screenshot(driver: webdriver.Firefox, url: str, path: str, width: int, height: int, overwrite: bool, verbose: bool) -> None:
    exists = os.path.exists(path)
    if (not exists) or (exists and overwrite):
        driver.set_window_size(width, height)
        driver.get(url)
        driver.save_screenshot(path)
    elif verbose:
        print(f"{path} exists and overwrite is disabled. Skipping screenshot.")


def screenshot_shodan(driver: webdriver.Firefox, target: Target, folder: str, verbose: bool = False, overwrite: bool = False) -> None:
    if target.type != TargetType.Address:
        raise UnsupportedTargetTypeError(target.type)

    screenshot_path = join(folder, "shodan.png")
    take_screenshot(driver, f"https://www.shodan.io/host/{target.name}",
        screenshot_path, 1000, 2000, overwrite=overwrite, verbose=verbose)


def screenshot_virustotal(driver: webdriver.Firefox, target: Target, folder: str, verbose: bool = False, overwrite: bool = False) -> None:
    detection_screenshot_path = join(folder, "virustotal_detection.png")
    summary_screenshot_path = join(folder, "virustotal_summary.png")

    if target.type == TargetType.Address:
        take_screenshot(driver,
            f"https://www.virustotal.com/gui/ip-address/{target.name}/detection",
            detection_screenshot_path, 1000, 2350, overwrite=overwrite, verbose=verbose)
        take_screenshot(driver,
            f"https://www.virustotal.com/gui/ip-address/{target.name}/summary",
            summary_screenshot_path, 500, 750, overwrite=overwrite, verbose=verbose)
    elif target.type == TargetType.Hash:
        take_screenshot(driver,
            f"https://www.virustotal.com/gui/file/{target.name}/detection",
            detection_screenshot_path, 1000, 2350, overwrite=overwrite, verbose=verbose)
    else:
        raise UnsupportedTargetTypeError(target.type)


def screenshot_threatcrowd(driver: webdriver.Firefox, target: Target, folder: str, verbose: bool = False, overwrite: bool = False) -> None:
    screenshot_path = join(folder, "threatcrowd.png")

    if target.type == TargetType.Address:
        take_screenshot(driver,
            f"https://threarcrowd.org/ip.php?ip={target.name}",
            screenshot_path, 1800, 1700, overwrite=overwrite, verbose=verbose)
    elif target.type == TargetType.Hash:
        take_screenshot(driver,
            f"https://threatcrowd.org/pivot.php?data={target.name}",
            screenshot_path, 1800, 1700, overwrite=overwrite, verbose=verbose)
    else:
        raise UnsupportedTargetTypeError(target.type)


def screenshot_alienvault_otx(driver: webdriver.Firefox, target: Target, folder: str, verbose: bool = False, overwrite: bool = False) -> None:
    screenshot_path = join(folder, "alienvault_otx.png")

    if target.type == TargetType.Address:
        take_screenshot(driver,
            f"https://otx.alienvault.com/indicator/ip/{target.name}",
            screenshot_path, 2000, 3000, overwrite=overwrite, verbose=verbose)
    elif target.type == TargetType.Hash:
        take_screenshot(driver,
            f"https://otx.alienvault.com/indicator/file/{target.name}",
            screenshot_path, 2000, 3000, overwrite=overwrite, verbose=verbose)
    else:
        raise UnsupportedTargetTypeError(target.type)
