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
import re
import jwt
import json
import plac
import requests

def get_wellknown_data():
    """
    Returns the wellknown URL's JSON
    >>> isinstance(get_wellknown_data(), dict)
    True
    """
    response = requests.get('https://api.byu.edu/.well-known/openid-configuration')
    response.raise_for_status()
    return response.json()

def get_jwks_data(jwks_uri):
    """
    Returns the JSON Web Keystore data in JSON format
    >>> jwks_data = get_jwks_data(get_wellknown_data()['jwks_uri'])
    >>> isinstance(jwks_data, dict)
    True
    >>> 'keys' in jwks_data
    True
    >>> len(jwks_data['keys']) >= 1
    True
    >>> 'x5c' in jwks_data['keys'][0]
    True
    """
    response = requests.get(jwks_uri)
    response.raise_for_status()
    return response.json()

def format_PEM(public_key):
    """
    >>> test_string = "1234567890123456789012345678901234567890123456789012345678901234567890123456789089012345678901234567890123456789012345678901234567890"
    >>> format_PEM(test_string).replace("\\n", "n")
    '-----BEGIN CERTIFICATE-----n1234567890123456789012345678901234567890123456789012345678901234n5678901234567890890123456789012345678901234567890123456789012345n67890n-----END CERTIFICATE-----'
    """
    public_key = re.sub(r"(.{64})", r"\1\n", public_key);
    prefix = "-----BEGIN CERTIFICATE-----\n";
    postfix = "\n-----END CERTIFICATE-----";
    return prefix + public_key + postfix;

def is_valid(jwt_to_validate):
    try:
        decode(jwt_to_validate)
        return True
    except Exception:
        return False

def decode(jwt_to_decode):
    """
    # TODO test by getting a JWT from the echo service
    """
    well_known = get_wellknown_data()
    jwks_data = get_jwks_data(well_known['jwks_uri'])
    print(jwks_data)
    return jwt.decode(jwt_to_decode,
                      format_PEM(jwks_data['keys'][0]['x5c']),
                      verify=True,
                      issuer=well_known['issuer'], 
                      leeway=2)

def test(verbose=False):
    import doctest
    doctest.testmod(verbose=verbose)

if __name__ == "__main__":
    plac.call(test)
