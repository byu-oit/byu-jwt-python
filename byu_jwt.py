#!/usr/bin/env python3
#
# Copyright 2016 Brigham Young University
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import print_function
import plac
import requests
import json
import jwt

def get_wellknown_data():
    """
    Returns the wellknown URL's JSON
    """
    response = requests.get('https://api.byu.edu/.well-known/openid-configuration')
    response.raise_for_status()
    return response.json()

def get_jwks_data(jwks_uri):
    """
    Returns the JSON Web Keystore data in JSON format
    """
    response = requests.get(jwks_uri)
    response.raise_for_status()
    return response.json()

def is_valid(jwt_to_validate):
    try:
        decode(jwt_to_validate)
        return True
    except Exception:
        return False

def decode(jwt_to_decode):
    return jwt.decode(jwt_to_decode, verify=True)

def test(verbose=False):
    """
    >>> is_valid(open('test_jwt').read())
    True
    """
    import doctest
    doctest.testmod(verbose=verbose)

if __name__ == "__main__":
    plac.call(test)
