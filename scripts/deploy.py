#!/usr/bin/env python2

"""
Deploy nightly builds.


To deploy to dropbox you need:
- Access to the wrye bash shared folder in your dropbox
- A dropbox API access token
  See: https://blogs.dropbox.com/developers/2014/05/generate-an-access-token-for-your-own-account/

To deploy to nexus you need:
- Your favourite browser installed
- A drive for your favourite browser available in PATH
  Chrome: https://sites.google.com/a/chromium.org/chromedriver/downloads
  Firefox: https://github.com/mozilla/geckodriver/releases
  Edge: https://developer.microsoft.com/en-us/microsoft-edge/tools/webdriver/
  Place it in PATH (e.g. in this script's folder or C:\Windows)
- To be logged in to nexusmods.com in your favourite browser
- A way to check cookie values in your favourite browser
  Chrome: chrome://settings/siteData
  Firefox: Shift+F9 when at nexusmods.com

Check the relevant subcommands for what values you need.

Unless '--no-config' is supplied, all values are saved to a
configuration file at './deploy_config.json'. Values are
stored as a dictionary with the format (keys in lowercase):
    '%SUBCOMMAND%_%ARGUMENT%': '%VALUE%'

Besides the config file and the cli arguments, you can also
provide the required values via environment variables. This
is only recommended for integration with CI servers. These
variables are in the format (keys in uppercase):
    'WRYE_BASH_%ARGUMENT%'='%VALUE%'
"""

import argparse

import deploy_dropbox
import deploy_nexus

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--no-config", help="Do not save to a config file.", action="store_true"
    )
    subparser = parser.add_subparsers(title="subcommands", dest="subcommand")
    sub_dropbox = subparser.add_parser("dropbox", help="Upload nightly to dropbox")
    deploy_dropbox.setup_parser(sub_dropbox)
    sub_nexus = subparser.add_parser("nexus", help="Upload nightly to nexus")
    deploy_nexus.setup_parser(sub_nexus)
    sub_all = subparser.add_parser("all", help="Upload nightly to all targets above")
    dropbox_group = sub_all.add_argument_group("dropbox arguments")
    deploy_dropbox.setup_parser(dropbox_group)
    nexus_group = sub_all.add_argument_group("nexus arguments")
    deploy_nexus.setup_parser(nexus_group)
    args = parser.parse_args()
    if args.subcommand in ("dropbox", "all"):
        deploy_dropbox.main(args)
    if args.subcommand in ("nexus", "all"):
        deploy_nexus.main(args)
