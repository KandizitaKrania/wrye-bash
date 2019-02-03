#!/usr/bin/env python2

import argparse
import json
import os
import re
from contextlib import closing, contextmanager

from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as ec
from selenium.webdriver.support.ui import Select, WebDriverWait

COOKIES_TEMPLATE = {
    "pass_hash": {
        "domain": ".nexusmods.com",
        "expiry": None,
        "httpOnly": False,
        "name": "pass_hash",
        "path": "/",
        "secure": True,
        "value": None,
    },
    "member_id": {
        "domain": ".nexusmods.com",
        "expiry": None,
        "httpOnly": False,
        "name": "member_id",
        "path": "/",
        "secure": True,
        "value": None,
    },
    "sid": {
        "domain": ".nexusmods.com",
        "expiry": None,
        "httpOnly": False,
        "name": "sid",
        "path": "/",
        "secure": True,
        "value": None,
    },
}
ID_DICT = {
    # oblivion
    101: 22369,
    # skyrim
    110: 1840,
    # skyrim special edition
    1704: 6837,
    # fallout 3
    120: 22934,
    # fallout new vegas
    130: 64580,
    # fallout 4
    1151: 20032,
}
DESC_DICT = {
    "Installer": (
        "Executable automated Installer. This will by default install "
        "just the Standalone Wrye Bash. It can also install all "
        "requirements for a full Python setup if you have any plans to "
        "join in with development."
    ),
    "Python Source": (
        "This is a manual installation of Wrye Bash Python files, "
        "requiring the full Python setup files to also be manually "
        "installed first."
    ),
    "Standalone Executable": (
        "This is a manual installation of the Wrye Bash " "Standalone files."
    ),
}
DRIVER_DOWNLOAD = (
    "Download the {} driver from {} and place it in this script's folder.\n"
    "Press Enter to continue..."
)
CATEGORY = "Updates"

ROOT_FOLDER = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(ROOT_FOLDER, "deploy_config.json")
DIST_PATH = os.path.join(ROOT_FOLDER, "dist")
assert os.path.isdir(DIST_PATH), "You don't have any files to upload."

FILE_REGEX = (
    r"Wrye Bash \d{3,}\.\d{12,12} - (Installer|Python Source|Standalone Executable)"
)
COMPILED_REGEX = re.compile(FILE_REGEX)


def check_executable(exename):
    return any(
        os.access(os.path.join(path, exename), os.X_OK)
        for path in os.environ["PATH"].split(os.pathsep)
    )


# https://blog.codeship.com/get-selenium-to-wait-for-page-load/
@contextmanager
def wait_for_page_load(browser, timeout=30):
    old_page = browser.find_element_by_tag_name("html")
    yield
    WebDriverWait(browser, timeout).until(ec.staleness_of(old_page))


def setup_parser(parser):
    parser.add_argument(
        "-d", "--driver", help="Choose a browser to use: firefox, chrome or edge"
    )
    parser.add_argument(
        "-m",
        "--member-id",
        help="The 'value' from the cookie 'member_id' in the domain 'nexusmods.com'",
    )
    parser.add_argument(
        "-p",
        "--pass-hash",
        help="The 'value' from the cookie 'pass_hash' in the domain 'nexusmods.com'",
    )
    parser.add_argument(
        "-s",
        "--sid",
        help="The 'value' from the cookie 'sid' in the domain 'nexusmods.com'",
    )


def parse_config(args):
    # the dict with "defaults"
    default_dict = {"driver": None, "member_id": None, "pass_hash": None, "sid": None}
    if os.path.isfile(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as conf_file:
            file_dict = json.load(conf_file)
    else:
        file_dict = {}
    for key in default_dict.keys():
        # load the config file (json)
        value = file_dict.get("nexus_" + key, None) or default_dict[key]
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
            file_dict.update({"nexus_" + a: b for a, b in default_dict.items()})
            json.dump(file_dict, conf_file, indent=2, separators=(",", ": "))
    return default_dict


def setup_driver(driver_name):
    if driver_name == "chrome":
        while not check_executable("chromedriver.exe"):
            raw_input(
                DRIVER_DOWNLOAD.format(
                    "chrome",
                    "https://sites.google.com/a/chromium.org/chromedriver/downloads",
                )
            )
        options = webdriver.ChromeOptions()
        options.add_argument("--ignore-certificate-errors")
        options.add_argument("--ignore-ssl-errors")
        return webdriver.Chrome(chrome_options=options)
    elif driver_name == "firefox":
        while not check_executable("geckodriver.exe"):
            raw_input(
                DRIVER_DOWNLOAD.format(
                    "firefox", "https://github.com/mozilla/geckodriver/releases/latest"
                )
            )
        profile = webdriver.FirefoxProfile()
        profile.accept_untrusted_certs = True
        return webdriver.Firefox(firefox_profile=profile)
    else:
        while not check_executable("MicrosoftWebDriver.exe"):
            raw_input(
                DRIVER_DOWNLOAD.format(
                    "edge",
                    "https://developer.microsoft.com/en-us/microsoft-edge"
                    "/tools/webdriver/#downloads",
                )
            )
        capabilities = webdriver.DesiredCapabilities().INTERNETEXPLORER
        capabilities["acceptSslCerts"] = True
        return webdriver.Ie(capabilities=capabilities)


def load_cookies(driver, config):
    cookies_dict = dict(COOKIES_TEMPLATE)
    for key, value in cookies_dict.items():
        cookies_dict[key]["value"] = config[key]
    driver.get("https://www.nexusmods.com")
    for cookie in cookies_dict.values():
        driver.add_cookie(cookie)


def set_file_to_replace(driver, name):
    xpath = "//div[@class='file-category']/h3[text()='Updates']/../ol/li"
    file_entries = driver.find_elements_by_xpath(xpath)
    for entry in file_entries:
        fname_xpath = "div[@class='file-head']/h4"
        fname = entry.find_element_by_xpath(fname_xpath).text
        if COMPILED_REGEX.match(fname) is None or not fname.endswith(name.split()[-1]):
            continue
        fversion_xpath = "div[@class='file-head']/div/span"
        fversion = entry.find_element_by_xpath(fversion_xpath).text
        freplace = " ".join((fname, fversion))
        driver.find_element_by_id("new-existing-version").click()
        Select(
            driver.find_element_by_id("select-original-file")
        ).select_by_visible_text(freplace)
        driver.find_element_by_id("remove-old-version").click()
        break


def upload_files(driver):
    for fname in os.listdir(DIST_PATH):
        fpath = os.path.join(DIST_PATH, fname)
        if not os.path.isfile(fpath):
            return
        name = os.path.splitext(fname)[0]
        version = name.split()[2]
        try:
            # handle cookies banner
            xpath = "//a[@class='banner_continue--2NyXA']"
            banner = WebDriverWait(driver, 5).until(
                ec.element_to_be_clickable((By.XPATH, xpath))
            )
            banner.click()
        except TimeoutException:
            pass
        # mod name
        driver.find_element_by_name("name").send_keys(name)
        # mod version
        driver.find_element_by_name("file-version").send_keys(version)
        # mod category
        Select(
            driver.find_element_by_id("select-file-category")
        ).select_by_visible_text(CATEGORY)
        # check if it is necessary to replace a previous file
        set_file_to_replace(driver, name)
        # mod description
        mod_desc = next(value for key, value in DESC_DICT.iteritems() if key in fname)
        driver.find_element_by_id("file-description").send_keys(mod_desc)
        # remove download with manager button
        driver.find_element_by_id("option-dlbutton").click()
        # upload the actual file
        driver.find_element_by_xpath("//input[@type='file']").send_keys(fpath)
        # Will wait 1 hour for file upload - no point in doing timeouts if goal is ci
        WebDriverWait(driver, 3600).until(
            ec.text_to_be_present_in_element(
                (By.XPATH, "//div[@id='file_uploader']/p"),
                fname + " has been uploaded.",
            )
        )
        # page will auto refresh after "saving" the new file
        with wait_for_page_load(driver):
            driver.find_element_by_xpath(
                "//div[@class='btn inline mod-add-file']"
            ).click()
        try:
            # fixme XXX: check if nexus actually opens an ad page
            tabs = driver.window_handles
            driver.switch_to.window(tabs[1])  # sometimes nexus opens an ad page
            driver.close()
            driver.switch_to.window(tabs[0])
        except IndexError:
            pass  # python 2 does not have `suppress` - for shame


def main(args):
    config = parse_config(args)
    driver = setup_driver(config["driver"])
    driver.maximize_window()
    load_cookies(driver, config)
    with closing(driver):
        for game_id, mod_id in ID_DICT.iteritems():
            driver.get(
                "https://www.nexusmods.com/mods/"
                "edit/?step=files&id={}&game_id={}".format(mod_id, game_id)
            )
            upload_files(driver)


if __name__ == "__main__":
    argparser = argparse.ArgumentParser()
    setup_parser(argparser)
    argparser.add_argument(
        "--no-config", help="Do not save to a config file.", action="store_true"
    )
    parsed_args = argparser.parse_args()
    main(parsed_args)
