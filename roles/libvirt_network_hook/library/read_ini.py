#!/usr/bin/env python

# -*- coding: utf-8 -*-
# (c) Copyright 2016 Sean "Shaleh" Perry
# (c) Copyright 2020 Dmitri Rubinstein
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
---
module: read_ini
short_description: Read settings in INI files
description:
     - Read individual settings in an INI-style file
version_added: "0.10"
options:
  path:
    description:
      - Path to the INI-style file
    required: true
    default: null
  section:
    description:
      - Section name in INI file.
    required: true
    default: null
  option:
    description:
      - Name of the option to read.
    required: true
    default: null
requirements: [ ConfigParser ]
author: Sean "Shaleh" Perry
'''

EXAMPLES = '''
# Read "fav" from section "[drinks]" in specified file.
- read_ini: path=/etc/conf section=drinks option=fav
'''

try:
  import ConfigParser as configparser
except ImportError:
  import configparser
import sys

from ansible.module_utils.basic import *


class ReadIniException(Exception):
    pass


def do_read_ini(module, filename, section=None, option=None):
    cp = configparser.ConfigParser()
    cp.optionxform = lambda x: x  # identity function to prevent casting

    try:
        with open(filename, 'rt') as fp:
          try:
            cp.read_file(fp, source=filename) # Python 3
          except AttributeError:
            cp.readfp(fp) # Python 2
    except IOError as e:
        raise ReadIniException("failed to read {}: {}".format(filename, e))

    try:
        if not section:
          value = dict()
          for section_name in cp.sections():
              section_dict = dict()
              value[section_name] = section_dict
              for option_name, option_value in cp.items(section_name):
                section_dict[option_name] = option_value
          return value

        if not option:
            value = dict()
            for option_name, option_value in cp.items(section):
                value[option_name] = option_value
            return value

        return cp.get(section, option)
    except configparser.NoSectionError:
        raise ReadIniException("section does not exist: " + section)
    except configparser.NoOptionError:
        raise ReadIniException("option does not exist: " + option)


def run_module():
    module_args = dict(
        path=dict(type='str', required=True),
        section=dict(type='str', required=False),
        option=dict(type='str', required=False)
    )
    module = AnsibleModule(
      argument_spec=module_args,
      supports_check_mode=True
    )

    path = os.path.expanduser(module.params['path'])
    section = module.params['section']
    option = module.params['option']

    try:
        value = do_read_ini(module, path, section, option)
        module.exit_json(path=path, changed=True, value=value)
    except ReadIniException as e:
        module.fail_json(msg=str(e))


def main():
    run_module()


if __name__ == '__main__':
    main()
