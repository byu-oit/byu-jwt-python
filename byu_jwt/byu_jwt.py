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
import fire
import base64
import requests
import subprocess
from OpenSSL import crypto 
from os.path import expanduser

BYU_JWT_HEADER_CURRENT = 'X-JWT-Assertion'
BYU_JWT_HEADER_ORIGINAL = 'X-JWT-Assertion-Original'

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

def add_byu_output_structure(decoded_jwt):
    """
    >>> output = add_byu_output_structure({u'http://wso2.org/claims/usertype': u'APPLICATION', u'http://byu.edu/claims/client_byu_id': u'111111111', u'http://byu.edu/claims/client_surname_position': u'L', u'http://byu.edu/claims/client_surname': u'Doe', u'http://wso2.org/claims/keytype': u'PRODUCTION', u'http://wso2.org/claims/apicontext': u'/echo/v1', u'http://byu.edu/claims/client_rest_of_name': u'John Douglas', u'http://wso2.org/claims/enduser': u'netid@carbon.super', u'http://byu.edu/claims/client_sort_name': u'Doe, John Douglas', u'http://byu.edu/claims/client_name_suffix': u' ', u'http://wso2.org/claims/applicationname': u'byu-jwt-python', u'http://byu.edu/claims/client_name_prefix': u' ', u'http://byu.edu/claims/client_person_id': u'222222222', u'http://byu.edu/claims/client_net_id': u'netid', u'http://wso2.org/claims/enduserTenantId': u'-1234', u'http://byu.edu/claims/client_subscriber_net_id': u'netid', u'http://byu.edu/claims/client_preferred_first_name': u'John', u'http://wso2.org/claims/tier': u'Gold', u'iss': u'https://api.byu.edu', u'http://wso2.org/claims/applicationtier': u'Gold', u'http://wso2.org/claims/applicationid': u'1111', u'http://wso2.org/claims/subscriber': u'BYU/netid', u'http://byu.edu/claims/client_claim_source': u'CLIENT_SUBSCRIBER', u'http://wso2.org/claims/version': u'v1', u'exp': 1492184412, u'http://wso2.org/claims/client_id': u'RANDOMWMT1INVALIDdj37dj39djei'})
    >>> all([key in output.keys() for key in ['byu', 'wso2']])
    True
    >>> all([key in output['byu'].keys() for key in ['client', 'webresCheck']])
    True
    >>> all([key in output['byu']['client'].keys() for key in ['byuId', 'claimSource', 'netId', 'personId', 'preferredFirstName', 'prefix', 'restOfName', 'sortName', 'subscriberNetId', 'suffix', 'surname', 'surnamePosition']])
    True
    >>> 'resourceOwner' not in output['byu']
    True
    >>> all([key in output['byu']['webresCheck'].keys() for key in ['byuId', 'netId', 'personId']])
    True
    >>> output['byu']['webresCheck']['byuId'] 
    u'111111111'
    >>> output = add_byu_output_structure({"iss": "https://api.byu.edu", "exp": 1492186348, "http://wso2.org/claims/subscriber": "BYU/netid", "http://wso2.org/claims/applicationid": "3333", "http://wso2.org/claims/applicationname": "testing", "http://wso2.org/claims/applicationtier": "Unlimited", "http://wso2.org/claims/apicontext": "/echo/v1", "http://wso2.org/claims/version": "1.0.0", "http://wso2.org/claims/tier": "Unlimited", "http://wso2.org/claims/keytype": "SANDBOX", "http://wso2.org/claims/usertype": "APPLICATION_USER", "http://wso2.org/claims/enduser": "netid@carbon.super", "http://wso2.org/claims/enduserTenantId": "-1234", "http://byu.edu/claims/resourceowner_suffix": " ", "http://byu.edu/claims/client_rest_of_name": "John Douglas", "http://byu.edu/claims/resourceowner_person_id": "555555555", "http://byu.edu/claims/resourceowner_byu_id": "333333333", "http://wso2.org/claims/client_id": "pkQWMIFwrXxqlQH7TWrm0VBvTJ8a", "http://byu.edu/claims/resourceowner_net_id": "netid", "http://byu.edu/claims/resourceowner_surname": "Malone", "http://byu.edu/claims/client_person_id": "666666666", "http://byu.edu/claims/client_sort_name": "Doe, John Douglas", "http://byu.edu/claims/client_claim_source": "CLIENT_SUBSCRIBER", "http://byu.edu/claims/client_net_id": "netid", "http://byu.edu/claims/client_subscriber_net_id": "netid", "http://byu.edu/claims/resourceowner_prefix": " ", "http://byu.edu/claims/resourceowner_surname_position": "L", "http://byu.edu/claims/resourceowner_rest_of_name": "Molly", "http://byu.edu/claims/client_name_suffix": " ", "http://byu.edu/claims/client_surname": "Doe", "http://byu.edu/claims/client_name_prefix": " ", "http://byu.edu/claims/client_surname_position": "L", "http://byu.edu/claims/resourceowner_preferred_first_name": "Molly", "http://byu.edu/claims/client_byu_id": "444444444", "http://byu.edu/claims/client_preferred_first_name": "John", "http://byu.edu/claims/resourceowner_sort_name": "Malone, Molly"})
    >>> 'resourceOwner' in output['byu']
    True
    >>> all([key in output['byu']['resourceOwner'].keys() for key in ['byuId', 'netId', 'personId', 'preferredFirstName', 'prefix', 'restOfName', 'sortName', 'suffix', 'surname', 'surnamePosition']])
    True
    >>> any([key in output['byu']['resourceOwner'].keys() for key in ['claimSource', 'subscriberNetId']])
    False
    >>> all([key in output['byu']['webresCheck'].keys() for key in ['byuId', 'netId', 'personId']])
    True
    >>> output['byu']['webresCheck']['byuId'] 
    '333333333'
    >>> all([key in output['wso2'].keys() for key in ['apiContext', 'application', 'clientId', 'endUser', 'endUserTenantId', 'keyType', 'subscriber', 'tier', 'userType', 'version']])
    True
    >>> all([key in output['wso2']['application'].keys() for key in ['id', 'name', 'tier']])
    True
    """
    decoded_jwt['byu'] = {}
    decoded_jwt['byu']['client'] = {}
    decoded_jwt['byu']['client']['byuId'] = decoded_jwt['http://byu.edu/claims/client_byu_id']
    decoded_jwt['byu']['client']['claimSource'] = decoded_jwt['http://byu.edu/claims/client_claim_source']
    decoded_jwt['byu']['client']['netId'] = decoded_jwt['http://byu.edu/claims/client_net_id']
    decoded_jwt['byu']['client']['personId'] = decoded_jwt['http://byu.edu/claims/client_person_id']
    decoded_jwt['byu']['client']['preferredFirstName'] = decoded_jwt['http://byu.edu/claims/client_preferred_first_name']
    decoded_jwt['byu']['client']['prefix'] = decoded_jwt['http://byu.edu/claims/client_name_prefix']
    decoded_jwt['byu']['client']['restOfName'] = decoded_jwt['http://byu.edu/claims/client_rest_of_name']
    decoded_jwt['byu']['client']['sortName'] = decoded_jwt['http://byu.edu/claims/client_sort_name']
    decoded_jwt['byu']['client']['subscriberNetId'] = decoded_jwt['http://byu.edu/claims/client_subscriber_net_id']
    decoded_jwt['byu']['client']['suffix'] = decoded_jwt['http://byu.edu/claims/client_name_suffix']
    decoded_jwt['byu']['client']['surname'] = decoded_jwt['http://byu.edu/claims/client_surname']
    decoded_jwt['byu']['client']['surnamePosition'] = decoded_jwt['http://byu.edu/claims/client_surname_position']
    decoded_jwt['byu']['webresCheck'] = {}
    if 'http://byu.edu/claims/resourceowner_person_id' in decoded_jwt:
        decoded_jwt['byu']['webresCheck']['byuId'] = decoded_jwt['http://byu.edu/claims/resourceowner_byu_id']
        decoded_jwt['byu']['webresCheck']['netId'] = decoded_jwt['http://byu.edu/claims/resourceowner_net_id']
        decoded_jwt['byu']['webresCheck']['personId'] = decoded_jwt['http://byu.edu/claims/resourceowner_person_id']
    else:
        decoded_jwt['byu']['webresCheck']['byuId'] = decoded_jwt['http://byu.edu/claims/client_byu_id']
        decoded_jwt['byu']['webresCheck']['netId'] = decoded_jwt['http://byu.edu/claims/client_net_id']
        decoded_jwt['byu']['webresCheck']['personId'] = decoded_jwt['http://byu.edu/claims/client_person_id']
    if 'http://byu.edu/claims/resourceowner_person_id' in decoded_jwt:
        decoded_jwt['byu']['resourceOwner'] = {}
        decoded_jwt['byu']['resourceOwner']['byuId'] = decoded_jwt['http://byu.edu/claims/resourceowner_byu_id']
        decoded_jwt['byu']['resourceOwner']['netId'] = decoded_jwt['http://byu.edu/claims/resourceowner_net_id']
        decoded_jwt['byu']['resourceOwner']['personId'] = decoded_jwt['http://byu.edu/claims/resourceowner_person_id']
        decoded_jwt['byu']['resourceOwner']['preferredFirstName'] = decoded_jwt['http://byu.edu/claims/resourceowner_preferred_first_name']
        decoded_jwt['byu']['resourceOwner']['prefix'] = decoded_jwt['http://byu.edu/claims/resourceowner_prefix']
        decoded_jwt['byu']['resourceOwner']['restOfName'] = decoded_jwt['http://byu.edu/claims/resourceowner_rest_of_name']
        decoded_jwt['byu']['resourceOwner']['sortName'] = decoded_jwt['http://byu.edu/claims/resourceowner_sort_name']
        decoded_jwt['byu']['resourceOwner']['suffix'] = decoded_jwt['http://byu.edu/claims/resourceowner_suffix']
        decoded_jwt['byu']['resourceOwner']['surname'] = decoded_jwt['http://byu.edu/claims/resourceowner_surname']
        decoded_jwt['byu']['resourceOwner']['surnamePosition'] = decoded_jwt['http://byu.edu/claims/resourceowner_surname_position']
    decoded_jwt['wso2'] = {}
    decoded_jwt['wso2']['apiContext'] = decoded_jwt['http://wso2.org/claims/apicontext']
    decoded_jwt['wso2']['application'] = {}
    decoded_jwt['wso2']['application']['id'] = decoded_jwt['http://wso2.org/claims/applicationid']
    decoded_jwt['wso2']['application']['name'] = decoded_jwt['http://wso2.org/claims/applicationname']
    decoded_jwt['wso2']['application']['tier'] = decoded_jwt['http://wso2.org/claims/applicationtier']
    decoded_jwt['wso2']['clientId'] = decoded_jwt['http://wso2.org/claims/client_id']
    decoded_jwt['wso2']['endUser'] = decoded_jwt['http://wso2.org/claims/enduser']
    decoded_jwt['wso2']['endUserTenantId'] = decoded_jwt['http://wso2.org/claims/enduserTenantId']
    decoded_jwt['wso2']['keyType'] = decoded_jwt['http://wso2.org/claims/keytype']
    decoded_jwt['wso2']['subscriber'] = decoded_jwt['http://wso2.org/claims/subscriber']
    decoded_jwt['wso2']['tier'] = decoded_jwt['http://wso2.org/claims/tier']
    decoded_jwt['wso2']['userType'] = decoded_jwt['http://wso2.org/claims/usertype']
    decoded_jwt['wso2']['version'] = decoded_jwt['http://wso2.org/claims/version']
    return decoded_jwt

def decode(jwt_to_decode):
    """
    >>> ans = decode(_get_test_jwt())
    >>> ans is not None
    True
    """
    well_known = get_wellknown_data()
    jwks_data = get_jwks_data(well_known['jwks_uri'])
    der_file = crypto.load_certificate(crypto.FILETYPE_ASN1, base64.b64decode(jwks_data['keys'][0]['x5c'][0])) 
    decoded_jwt = jwt.decode(jwt_to_decode,
                      der_file.get_pubkey().to_cryptography_key(),
                      verify=True,
                      issuer=well_known['issuer'], 
                      leeway=2,
                      algorithm=['RS256'])
    decoded_jwt = add_byu_output_structure(decoded_jwt)
    return decoded_jwt

def test(verbose=False):
    import doctest
    doctest.testmod(verbose=verbose)

def _output(cmd):
    """
    >>> _output('echo "testing"')
    'testing\\n'
    """
    return subprocess.check_output(cmd, shell=True)

def _shell(cmd):
    """
    >>> _shell('echo ""')
    Running \"echo \"\"\"...
    """
    print('Running "{}"...'.format(cmd))
    subprocess.check_call(cmd, shell=True)

def deploy():
    _shell('python setup.py sdist')
    _shell('twine upload dist/*')
    _shell('python setup.py clean')

if __name__ == "__main__":
    fire.Fire()
