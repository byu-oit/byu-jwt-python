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
import sys
import json
import yaml
import plac
import base64
import requests
from OpenSSL import crypto 
from os.path import expanduser

def get_wellknown_data():
    """
    Returns the wellknown URL's JSON
    >>> isinstance(get_wellknown_data(), dict)
    True
    """
    response = requests.get('https://api.byu.edu/.well-known/openid-configuration', headers={'User-Agent': 'BYU-JWT-Python-SDK/1.0 (Python {})'.format(sys.version.replace('\n', ''))})
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

def _get_test_jwt():
    # curl -k -d "grant_type=client_credentials" -u "client_id:client_secret" https://api.byu.edu/token
    # {"scope":"default","token_type":"bearer","expires_in":3600,"refresh_token":"refresh_token","access_token":"access_token"}
    conf = yaml.load(open('{}/.byu/byu-jwt-python.yaml'.format(expanduser('~'))))
    response = requests.post('https://api.byu.edu/token', auth=(conf['client_id'], conf['client_secret']), data={'grant_type': 'client_credentials'})
    response.raise_for_status()
    access_token = response.json()['access_token']
    # curl -X GET --header "Accept: application/json" --header "Authorization: Bearer aaaaaaaaaaaaaaaaaaaaaaa" "https://api.byu.edu/echo/v1/echo/{+echo_string}"
    response = requests.get('https://api.byu.edu/echo/v1/echo/testing', headers={'Authorization': 'Bearer ' + access_token, 'Accept': 'application/json'})
    jwt = response.json()['Headers']['X-Jwt-Assertion'][0]
    return jwt

def is_valid(jwt_to_validate):
    """
    All of the encode and decode stuff here is for python2 and python3 compatibility
    >>> test_jwt = _get_test_jwt()
    >>> is_valid(test_jwt)
    True
    >>> header, body, signature = test_jwt.split('.')
    >>> decoded_jwt = json.loads(base64.b64decode(str(body) + '===').decode('utf-8'))
    >>> decoded_jwt['iss'] = 'http://fake.com'
    >>> invalid_jwt = header + '.' + base64.b64encode(json.dumps(decoded_jwt).encode('utf-8')).decode('utf-8') + '.' + signature
    >>> is_valid(invalid_jwt)
    False
    """
    try:
        decode(jwt_to_validate)
        return True
    except Exception:
        return False

def decode(jwt_to_decode):
    """
    >>> ans = decode(_get_test_jwt())
    >>> ans is not None
    True
    """
    well_known = get_wellknown_data()
    jwks_data = get_jwks_data(well_known['jwks_uri'])
    der_file = crypto.load_certificate(crypto.FILETYPE_ASN1, base64.b64decode(jwks_data['keys'][0]['x5c'][0])) 
    return jwt.decode(jwt_to_decode,
                      der_file.get_pubkey().to_cryptography_key(),
                      verify=True,
                      issuer=well_known['issuer'], 
                      leeway=2,
                      algorithm=['RS256'])

def test(verbose=False):
    import doctest
    doctest.testmod(verbose=verbose)

if __name__ == "__main__":
    plac.call(test)
