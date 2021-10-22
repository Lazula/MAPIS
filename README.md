# MAPIS: Multi-API Search

MAPIS is a command-line tool which collects data about the reputation of IP
addresses and sample hashes from multiple API endpoints using preconfigured key
data, provided in files or directly on the command line. It is intended
primarily for use by SOC analysts. To support this purpose, its features
emphasize the ability to record and report findings, e.g. by optionally
writing responses to disk and taking screenshots of web endpoints. MAPIS aims
to be highly configurable and adaptable to various workflows.

## Usage

Note that both IP addresses and hashes can be queried - the program is smart
enough to recognize a valid IP address and reject a hash if it contains invalid
characters, though it does not verify hash length. Input can be provided to the
program in multiple ways:

* `-n/--stdin`: Enter manually in interactive mode or read from a pipe
* `-t/--target-list`: Directly in program invocation via comma-separated list
* `-T/--target-file`: A file containing one entry per line

In interactive mode, use `help` to show a list of available commands.

## Screenshots

Screenshots can be enabled with `-s/--screenshot` and will be placed in the
folder given by `-s/--screenshot-folder` (default `screenshots/`). They are
slow and intended for use after confirming that a result is of interest. By
default, existing screenshots are not overwritten to speed up repeated requests
made with the screenshot option enabled. Use `--force-screenshot` to disable
this behavior. Screenshots are not subject to a disk quota.

### Geckodriver

Mozilla [geckodriver](https://github.com/mozilla/geckodriver/releases) is used
for taking screenshots. If the binary is not present in your system PATH and
executable, screenshots cannot be taken.

## API usage

### API keys

API keys must be provided in files in the directory given by `--keydir`
(default `API_KEYS/`). Individual API keys may also be provided via command
line arguments. See the program help for specific options.

### Caching responses to disk

Response data is stored in a dictionary in memory and updated with each
request. A single master print function passes the appropriate API data to each
API-specific print function. API responses may be cached by dumping the
internal JSON data structure to a file. Cached responses are checked for before
each new request unless explicitly disabled with the `--no-cache` option. When
a response is written, it is placed under the cache folder defined by
`--cache-folder` (`response_cache/` by default), then `hash/` or `address/`,
with a file name of the literal target string with `.cache.json` appended to it.

Caching may optionally be made subject to a disk quota with the `--disk-quota`
option. A size may be configured with `--disk-quota-size SIZE`, where SIZE is a
simple number of bytes (e.g. `1000`) or a human-readable string. Both base 10
and base 2 units are supported (e.g. `5G`, `800MiB`, `60Ki`), as well as
decimals (e.g. `50.5K`). The default quota size is 1 Gibibyte.

`--disk-quota-strategy {fifo,keep}` can be used to specify the quota strategy.
The `fifo` ("first-in-first-out") strategy discards the oldest entries to make
space for new ones. The `keep` strategy simply stops caching entries and
discards them if they would exceed the quota. The default strategy is `keep`.
`fifo` is not recommended when the amount of inputs greatly exceeds the
available cache size. **Please keep in mind the potential for this option to
cause high stress on storage media. Exercise caution.** Using a ramdisk can
help alleviate these problems, at the risk of volatility in case of power loss.

### Adding APIs

Adding additional APIs should be relatively straightforward by modeling the
process after existing code. If you would like to contribute in this way,
please take existing style and conventions into account.

## License (GNU GPLv3 or later)

    MAPIS: Multi-API Search - Identify malicious hosts and hashes
    Copyright (C) 2020-2021 Lazula

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
