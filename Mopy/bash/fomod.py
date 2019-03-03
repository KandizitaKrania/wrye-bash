# -*- coding: utf-8 -*-
#
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


__author__ = "Ganda"

import os
from collections import Sequence
from distutils.version import LooseVersion
from xml.etree import ElementTree as etree

from .bolt import Path
from .load_order import cached_is_active


class FailedCondition(Exception):
    pass


class InstallerPage(Sequence):
    def __init__(self, installer, page):
        self._installer = installer
        self._object = page
        self._group_list = installer._order_list(
            [
                InstallerGroup(installer, group)
                for group in page.findall("optionalFileGroups/*")
            ],
            page.get("order", "Ascending"),
        )
        self.name = page.get("name")

    def __getitem__(self, key):
        return self._group_list[key]

    def __len__(self):
        return len(self._group_list)


class InstallerGroup(Sequence):
    def __init__(self, installer, group):
        self._installer = installer
        self._object = group
        self._option_list = installer._order_list(
            [
                InstallerOption(installer, option)
                for option in group.findall("plugins/*")
            ],
            group.get("order", "Ascending"),
        )
        self.name = group.get("name")
        self.type = group.get("type")

    def __getitem__(self, key):
        return self._option_list[key]

    def __len__(self):
        return len(self._option_list)


class InstallerOption(object):
    def __init__(self, installer, option):
        self._installer = installer
        self._object = option
        self.name = option.get("name")
        self.description = option.findtext("description", "").strip()
        image = option.find("image")
        if image is not None:
            self.image = image.get("path")
        else:
            self.image = ""
        type_elem = option.find("typeDescriptor/type")
        if type_elem is not None:
            self.type = type_elem.get("name")
        else:
            default = option.find("typeDescriptor/dependencyType/defaultType").get(
                "name"
            )
            patterns = option.findall("typeDescriptor/dependencyType/patterns/*")
            for pattern in patterns:
                try:
                    self._installer._test_conditions(pattern.find("dependencies"))
                except FailedCondition:
                    pass
                else:
                    self.type = pattern.find("type").get("name")
                    break
            else:
                self.type = default


class PageInfo(object):
    def __init__(self, page, options):
        self.page = page
        self.options = options


class FileInfo(object):
    def __init__(self, source, destination, priority):
        self.source = source
        self.destination = destination
        self.priority = priority

    @classmethod
    def process_files(cls, files_elem, file_list):
        result = []
        for file_object in files_elem.findall("*"):
            print etree.tostring(file_object)
            source = file_object.get("source")
            if source.endswith(("/", "\\")):
                source = source[:-1]
            source = Path(source)
            destination = file_object.get("destination", None)
            if destination is None:  # omitted destination
                destination = source
            elif file_object.tag == "file" and (
                not destination or destination.endswith(("/", "\\"))
            ):
                # if empty or with a trailing slash then dest refers
                # to a folder. Post-processing to add the filename to the
                # end of the path.
                destination = Path(destination).join(Path(source).tail)
            else:
                # destination still needs normalizing
                destination = Path(destination)
            priority = int(file_object.get("priority", "0"))
            print source, destination, priority
            for fname in file_list:
                if fname.lower() == source.s.lower():  # it's a file
                    result.append(cls(source, destination, priority))
                elif fname.lower().startswith(source.s.lower()):  # it's a folder
                    source_len = len(source)
                    fdest = destination.s + fname[source_len:]
                    if fdest.startswith(os.sep):
                        fdest = fdest[1:]
                    result.append(cls(Path(fname), Path(fdest), priority))
        return result


class FomodInstaller(object):
    def __init__(self, root, file_list, dst_path, game_version):
        self.tree = etree.parse(root)
        self.fomod_name = self.tree.findtext("moduleName", "").strip()
        self.file_list = file_list
        self.dst_path = dst_path
        self.game_version = game_version
        self._current_page = None
        self._previous_pages = []
        self._has_finished = False

    def start(self):
        root_conditions = self.tree.find("moduleDependencies")
        if root_conditions is not None:
            self._test_conditions(root_conditions)
        first_page = self.tree.find("installSteps/installStep")
        if first_page is None:
            return None
        self._current_page = InstallerPage(self, first_page)
        return self._current_page

    def next_(self, selection):
        if self._has_finished or self._current_page is None:
            return None
        sort_list = [option for group in self._current_page for option in group]
        sorted_selection = sorted(selection, key=sort_list.index)
        self._previous_pages.append(PageInfo(self._current_page, sorted_selection))
        ordered_pages = self._order_list(
            self.tree.findall("installSteps/installStep"),
            self.tree.find("installSteps").get("order", "Ascending"),
        )
        current_index = ordered_pages.index(self._current_page._object)
        for page in ordered_pages[current_index + 1 :]:
            try:
                conditions = page.find("visible")
                if conditions is not None:
                    self._test_conditions(conditions)
            except FailedCondition:
                pass
            else:
                self._current_page = InstallerPage(self, page)
                return self._current_page
        else:
            self._has_finished = True
            self._current_page = None
        return None

    def previous(self):
        self._has_finished = False
        try:
            info = self._previous_pages.pop()
            self._current_page = info.page
            return info.page, info.options
        except IndexError:
            self._current_page = None
            return None

    def files(self):
        required_files = []
        required_files_elem = self.tree.find("requiredInstallFiles")
        if required_files_elem is not None:
            required_files = FileInfo.process_files(required_files_elem, self.file_list)
        user_files = []
        selected_options = [
            option._object for info in self._previous_pages for option in info.options
        ]
        for option in selected_options:
            option_files = option.find("files")
            if option_files is not None:
                user_files.extend(FileInfo.process_files(option_files, self.file_list))
        conditional_files = []
        for pattern in self.tree.findall("conditionalFileInstalls/patterns/pattern"):
            conditions = pattern.find("dependencies")
            files = pattern.find("files")
            try:
                self._test_conditions(conditions)
            except FailedCondition:
                pass
            else:
                conditional_files.extend(FileInfo.process_files(files, self.file_list))
        file_dict = {}  # dst -> src
        priority_dict = {}  # dst -> priority
        for info in required_files + user_files + conditional_files:
            if info.destination in priority_dict:
                if priority_dict[info.destination] > info.priority:
                    continue
                del file_dict[info.destination]
            file_dict[info.destination] = info.source
            priority_dict[info.destination] = info.priority
        # return everything in strings
        return {a.s: b.s for a, b in file_dict.iteritems()}

    def _flags(self):
        flag_dict = {}
        flags_list = [
            option._object.find("conditionFlags")
            for info in self._previous_pages
            for option in info.options
        ]
        for flags in flags_list:
            if flags is None:
                continue
            for flag in flags.findall("flag"):
                flag_name = flag.get("name")
                flag_value = flag.text
                flag_dict[flag_name] = flag_value
        return flag_dict

    def _test_file_condition(self, file_name, file_type):
        file_path = self.dst_path.join(file_name)
        if not file_path.exists():
            actual_type = "Missing"
        else:
            is_active = cached_is_active(file_name)
            if is_active:
                actual_type = "Active"
            else:
                actual_type = "Inactive"
        if actual_type != file_type:
            raise FailedCondition(
                "File {} should be {} but is {} intead.".format(
                    file_name, file_type, actual_type
                )
            )

    def _test_flag_condition(self, flag_name, flag_value):
        actual_value = self._flags().get(flag_name, None)
        if actual_value != flag_value:
            raise FailedCondition(
                "Flag {} was expected to have {} but has {} instead.".format(
                    flag_name, flag_value, actual_value
                )
            )

    def _test_version_condition(self, version):
        game_version = LooseVersion(self.game_version)
        version = LooseVersion(version)
        if game_version < version:
            raise FailedCondition(
                "Game version is {} but {} is required.".format(game_version, version)
            )

    def _test_conditions(self, conditions):
        op = conditions.get("operator", "And")
        failed = []
        condition_list = conditions.findall("*")
        for condition in condition_list:
            try:
                if condition.tag == "fileDependency":
                    file_name = condition.get("file")
                    file_type = condition.get("state")
                    self._test_file_condition(file_name, file_type)
                elif condition.tag == "flagDependency":
                    flag_name = condition.get("flag")
                    flag_value = condition.get("value")
                    self._test_flag_condition(flag_name, flag_value)
                elif condition.tag == "gameDependency":
                    version = condition.get("version")
                    self._test_version_condition(version)
                elif condition.tag == "dependencies":
                    self._test_conditions(condition)
            except FailedCondition as exc:
                failed.extend([a for a in str(exc).splitlines()])
                if op == "And":
                    raise FailedCondition("\n".join(failed))
        if op == "Or" and len(failed) == len(condition_list):
            raise FailedCondition("\n".join(failed))

    @staticmethod
    def _order_list(unordered_list, order):
        if order == "Explicit":
            return unordered_list
        elif order == "Ascending":
            return sorted(unordered_list, key=lambda x: x.name)
        elif order == "Descending":
            return sorted(unordered_list, key=lambda x: x.name, reverse=True)
        else:
            raise ValueError(
                "Arguments are incorrect: {}, {}".format(unordered_list, order)
            )
