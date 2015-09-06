# Curdling - Concurrent package manager for Python
# Copyright (C) 2013  Lincoln Clarete <lincoln@clarete.li>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, print_function, unicode_literals
from distlib import compat, util
from base64 import b64encode

import io
import os
import re
import hashlib
import logging
import subprocess
import urllib3


INCLUDE_PATTERN = re.compile(r'-r\s*\b([^\b]+)')
LINK_PATTERN = re.compile(r'^([^\:]+):\/\/.+')
ROOT_LOGGER = logging.getLogger('curdling')


class Requirement(object):
    def __init__(self, spec):
        """
        Takes a line from a requirements file or a single argument from the
        command line and parses, determining constraints. Also contains helper
        to download the requirement.
        """
        # needs to handle
        # tarball input
        # packagename
        # packagename==xxx
        # packagename>=xxx
        # packagename<=xxx
        # packagename>xxx
        # packagename<xxx

        # git+https://myvcs.com/some_dependency@sometag#egg=SomeDependency
        # -i, --index-url
        # --extra-index-url
        # --no-index
        # -f, --find-links
        # --allow-external
        # --allow-all-external
        # --allow-unverified
        # --no-binary
        # --only-binary

        # Check if the requriement is a tarball
        tarballs = [pkg for pkg in args.packages
                    if os.path.isfile(pkg) and acceptable_file_type(pkg)]
        args.packages = [pkg for pkg in args.packages if pkg not in tarballs]

        if not is_url(spec):
            requirement = util.parse_requirement(spec)
            requirement.name = safe_name(requirement.name)
            requirement.requirement = safe_requirement(spec)
            requirement.is_link = False
        else:
            requirement = Requirement()
            requirement.name = spec
            requirement.requirement = spec
            requirement.constraints = ()
            requirement.is_link = True
            requirement.extras = ()
        return requirement
    """
    TODO init
    TODO add force-reinstall
    TODO add allow-external
    TODO add allow-unverified
    """
    name = None


def is_url(requirement):
    """
    TODO urlparse for validity, reconstruct
    """
    return '://' in requirement

#
#def safe_name(str_requirement):
#    """
#    Cleanses names (removes _, uppercase) if they are not URLs
#    TODO handle git urls
#    TODO handle urls with eggname and version numbers
#    """
#    if is_url(str_requirement):
#        return str_requirement
#    else:
#        safe_requirement(str_requirement)
#
#
#def safe_requirement(requirement):
#    """
#    Converts _ to -, creates the Requriement
#    """
#    safe = requirement.lower().replace('_', '-')
#    parsed = util.parse_requirement(safe)
#    output = parsed.name
#    if parsed.extras:
#        output += '[{0}]'.format(','.join(parsed.extras))
#    if parsed.constraints:
#        def c(operator, version):
#            return version if operator == '==' \
#                else '{0} {1}'.format(operator, version)
#        output += ' ({0})'.format(
#            ', '.join(c(*i) for i in parsed.constraints))
#    return output
#
#
#def safe_constraints(spec):
#    if is_url(spec):
#        return None
#    constraints = util.parse_requirement(spec).constraints or ()
#    constraint = lambda k, v: \
#        ('{0} {1}'.format(k, v)
#         .replace('== ', '')
#         .replace('==', ''))
#    return ', '.join(constraint(k, v) for k, v in constraints) or None
#
#
#
#
#def parse_requirement(spec):
#    if not is_url(spec):
#        requirement = util.parse_requirement(spec)
#        requirement.name = safe_name(requirement.name)
#        requirement.requirement = safe_requirement(spec)
#        requirement.is_link = False
#    else:
#        requirement = Requirement()
#        requirement.name = spec
#        requirement.requirement = spec
#        requirement.constraints = ()
#        requirement.is_link = True
#        requirement.extras = ()
#    return requirement


def split_name(fname):
    name, ext = os.path.splitext(fname)

    try:
        ext, frag = ext.split('#')
    except ValueError:
        frag = ''
    return name, ext[1:], frag


def expand_requirements(open_file):
    """
    Takes a requirements file and expands it ito a list of Requirement Classes
    """
    requirements = []

    for req in open_file.read().splitlines():
        req = req.split('#', 1)[0].strip()
        if not req:
            continue

        # Handling special lines that start with `-r`, so we can have files
        # including other files.
        include = INCLUDE_PATTERN.findall(req)
        if include:
            requirements.extend(expand_requirements(io.open(include[0])))
            continue

        # Finally, we're sure that it's just a package description
        requirements.append(safe_name(req))
    return requirements


def filehash(f, algo, block_size=2**20):
    algo = getattr(hashlib, algo)()
    while True:
        data = f.read(block_size)
        if not data:
            break
        algo.update(data)
    return algo.hexdigest()


def spaces(count, text):
    return '\n'.join('{0}{1}'.format(' ' * count, line)
        for line in text.splitlines())


def get_auth_info_from_url(url, proxy=False):
    parsed = compat.urlparse(url)
    if parsed.username:
        auth = '{0}:{1}'.format(parsed.username, parsed.password)

        # The caller is not interested in proxy headers
        if not proxy:
            return urllib3.util.make_headers(basic_auth=auth)

        # Proxy-Authentication support
        return {'proxy-authorization':
            'Basic ' + b64encode(auth.encode('utf-8')).decode('ascii')}
    return {}


def execute_command(name, *args, **kwargs):
    command = subprocess.Popen((name,) + args,
        env=os.environ,
        stderr=subprocess.PIPE, stdout=subprocess.PIPE,
        **kwargs)
    _, errors = command.communicate()
    if command.returncode != 0:
        raise Exception(errors)


def logger(name):
    logger_instance = logging.getLogger(name)
    logger_instance.parent = ROOT_LOGGER
    return logger_instance
