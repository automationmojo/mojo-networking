# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

import configparser
import os


THIS_DIR = os.path.abspath(os.path.dirname(__file__))
REPOSITORY_FOLDER = os.path.abspath(os.path.join(THIS_DIR, "..", "..", ".."))
REPOSITORY_CONFIG_FILE = os.path.abspath(os.path.join(THIS_DIR, "repository-setup", "repository-config.ini"))


# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = '<project name>'
copyright = '2023, <author name>'
author = '<author name>'

if os.path.exists(REPOSITORY_CONFIG_FILE):
    config = configparser.ConfigParser()
    config.read(REPOSITORY_CONFIG_FILE)
    if "DEFAULT" in config:
        default_config = config["DEFAULT"]

        if "PROJECT_NAME" in default_config:
            project = default_config["PROJECT_NAME"]

        if "COPYRIGHT" in default_config:
            copyright = default_config["COPYRIGHT"]
        
        if "AUTHOR_NAME" in default_config:
            author = default_config["AUTHOR_NAME"]


# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = []

templates_path = ['_templates']
exclude_patterns = []



# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'alabaster'
html_static_path = ['_static']
