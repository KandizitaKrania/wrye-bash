#!/usr/bin/env python2

import argparse
import json
import os
import re

import dropbox

# constants
SHARED_FOLDER_ID = "4796182912"
ROOT_FOLDER = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(ROOT_FOLDER, "deploy_config.json")
DIST_PATH = os.path.join(ROOT_FOLDER, "dist")
assert os.path.isdir(DIST_PATH), "You don't have any files to upload."

# regex
FILE_REGEX = r"Wrye Bash \d{3,}\.\d{12,12} - (Installer.exe|Python Source.7z|Standalone Executable.7z)"
COMPILED = re.compile(FILE_REGEX)


def setup_parser(parser):
    parser.add_argument(
        "-t",
        "--access-token",
        help="The dropbox API access token.\n"
        "  To get your own access token\n"
        "  go to https://www.dropbox.com/developers/apps\n"
        "  register an app and generate your token.",
    )
    parser.add_argument(
        "-b",
        "--branch",
        help="Upload a specific branch.\n"
        "  Will upload to a separate folder\n"
        "  within the shared folder.",
    )


def parse_config(args):
    # the dict with "defaults"
    default_dict = {"access_token": None, "branch": ""}
    if os.path.isfile(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as conf_file:
            file_dict = json.load(conf_file)
    else:
        file_dict = {}
    for key in default_dict.keys():
        # load the config file (json)
        value = file_dict.get("dropbox_" + key, None) or default_dict[key]
        # load the environment variables - useful for ci deployment
        value = os.environ.get("WRYE_BASH_" + key, None) or value
        # load the cli arguments
        value = args.__getattribute__(key) or value
        # check for missing values
        if value is None:
            print "No {} specified, please enter it now:".format(key)
            value = raw_input("> ")
        default_dict[key] = value
    if not args.no_config:
        with open(CONFIG_FILE, "w") as conf_file:
            file_dict.update({"dropbox_" + a: b for a, b in default_dict.items()})
            json.dump(file_dict, conf_file, indent=2, separators=(",", ": "))
    return default_dict


def remove_files(dbx, path):
    # get all files in folder
    files = []
    for entry in dbx.files_list_folder(path).entries:
        if isinstance(entry, dropbox.files.FileMetadata):
            files.append(entry.name)
    # delete the previous nightly files
    filtered = filter(COMPILED.match, files)
    for fname in filtered:
        fpath = path + "/" + fname
        print "Removing {}...".format(fpath)
        dbx.files_delete_v2(fpath)


def upload_files(dbx, path):
    # upload new nightly
    for fname in os.listdir(DIST_PATH):
        fpath = os.path.join(DIST_PATH, fname)
        if not os.path.isfile(fpath):
            continue
        upload_path = path + "/" + fname
        with open(fpath, "rb") as fopen:
            print "Uploading {} to {}...".format(fpath, upload_path)
            dbx.files_upload(fopen.read(), upload_path)


def main(args):
    config = parse_config(args)
    # setup dropbox instance
    dbx = dropbox.Dropbox(config["access_token"])
    shared_folder_path = dbx.sharing_get_folder_metadata(SHARED_FOLDER_ID).path_lower
    # create folder inside shared folder if needed for branch nightly
    if config["branch"]:
        shared_folder_path += "/" + config["branch"]
        try:
            dbx.files_create_folder_v2(shared_folder_path)
        except dropbox.exceptions.ApiError:
            pass
    remove_files(dbx, shared_folder_path)
    upload_files(dbx, shared_folder_path)


if __name__ == "__main__":
    argparser = argparse.ArgumentParser()
    setup_parser(argparser)
    argparser.add_argument(
        "--no-config", help="Do not save to a config file.", action="store_true"
    )
    parsed_args = argparser.parse_args()
    main(parsed_args)
