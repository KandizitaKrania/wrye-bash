#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# GPL License and Copyright Notice ============================================
#  This file is part of Wrye Bash.
#
#  Wrye Bash is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.
#
#  Wrye Bash is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with Wrye Bash; if not, write to the Free Software Foundation,
#  Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
#  Wrye Bash copyright (C) 2005-2009 Wrye, 2010-2019 Wrye Bash Team
#  https://github.com/wrye-bash
#
# =============================================================================

"""
Builds and packages Wrye Bash.

There are three separate steps in the build process:
 - LOOT Python API - Wrye Bash requires these files which are not available
                     in PyPI;
 - Taglist Update  - Updates the taglists according to the given LOOT
                     revision;
 - Packaging       - Builds the executable if necessary and packages the
                     distributables for release.

Creates three different types of distributables:
 - Manual     - the python source files, requires Wrye Bash's development
                dependencies to run;
 - Standalone - a portable distributable with the pre-built executable;
 - Installer  - a binary distribution containing a custom installer.

Most steps of the build process can be customized, see the options below.
"""

import argparse

import build_loot_api
import build_package
import build_taglist
import build_utils

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    build_utils.setup_common_parser(parser)
    parser.add_argument(
        "--no-loot",
        action="store_false",
        dest="loot",
        help="Do not install loot's python API.",
    )
    parser.add_argument(
        "--no-tag",
        action="store_false",
        dest="tag",
        help="Do not update the tag lists.",
    )
    parser.add_argument(
        "--no-package",
        action="store_false",
        dest="package",
        help="Do not build a distributable package.",
    )
    loot_parser = parser.add_argument_group("loot api arguments")
    build_loot_api.setup_parser(loot_parser)
    tag_parser = parser.add_argument_group("tag list arguments")
    build_taglist.setup_parser(tag_parser)
    package_parser = parser.add_argument_group("package arguments")
    build_package.setup_parser(package_parser)
    args = parser.parse_args()
    open(args.logfile, "w").close()
    if args.loot:
        build_loot_api.main(args)
        print
    if args.tag:
        build_taglist.main(args)
        print
    if args.package:
        build_package.main(args)
