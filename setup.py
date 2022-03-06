#!/usr/bin/env python
# Copyright 2022 The Wazo Authors  (see the AUTHORS file)
# SPDX-License-Identifier: GPL-3.0-or-later

import yaml

from setuptools import find_packages
from setuptools import setup

with open('wazo/plugin.yml') as file:
    metadata = yaml.load(file, yaml.Loader)

setup(
    name=metadata['name'],
    version=metadata['version'],
    description=metadata['display_name'],
    author=metadata['author'],
    url=metadata['homepage'],
    packages=find_packages(),
    include_package_data=True,
    package_data={
        'wazo_presence_teams': ['*/api.yml'],
    },
    entry_points={
        'wazo_chatd.plugins': ['presence_teams = wazo_presence_teams.chatd.plugin:Plugin'],
    },
)
