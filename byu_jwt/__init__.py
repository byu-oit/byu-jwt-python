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
import json
import time
from datetime import datetime, timedelta
import jwt
import base64
import hashlib
import sys
import requests


class BYU_JWT(object):
    """BYU_JWT Wraps the process of verifing the BYU JWT"""
    BYU_JWT_HEADER_CURRENT = 'X-JWT-Assertion'  # TODO Not used probably remove
    BYU_JWT_HEADER_ORIGINAL = 'X-JWT-Assertion-Original'  # TODO Not used probably remove
    base_url = ""
    jwks_data = {'pubkeys': {}, 'issuer': {}, 'ttl': 0}

    def __init__(self, base_url="https://api.byu.edu"):
        self.base_url = base_url

    def get_signing_cert(self):
        """
        Returns public jwks cert data from cache or fetches if needed
        """
        if time.time() > self.jwks_data['ttl']:
            well_known = self._get_wellknown_data()
            self.jwks_data['issuer'] = well_known['issuer']
            jwks, ttl = self._get_jwks_data(well_known['jwks_uri'])
            self.jwks_data['pubkeys'] = self._extract_public_keys(jwks)
            self.jwks_data['ttl'] = ttl
        return self.jwks_data['pubkeys']

    def _extract_public_keys(self, jwks):
        # TODO Need to unit test as this is undocumented feature of pyjwt library
        key_set = {}
        for key in jwks['keys']:
            thumbprint = self.generate_x5t_from_x5c(key['x5c'][0])
            key_set[thumbprint] = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
        return key_set

    @staticmethod
    def generate_x5t_from_x5c(x5c):
        h = hashlib.sha1(base64.b64decode(x5c))
        t = base64.b64encode(h.hexdigest().encode())
        # remove padding
        t = t.decode().replace('=', '')
        return t

    @staticmethod
    def extract_x5t_from_jwt(_jwt):
        headers = _jwt.split('.')[0]
        headers = json.loads(base64.b64decode(headers))
        return headers['x5t']

    def _get_wellknown_data(self):
        """
        Returns the wellknown URL's JSON
        >>> isinstance(get_wellknown_data(), dict)
        True
        """
        url = '{}/.well-known/openid-configuration'.format(self.base_url)
        response = requests.get(url, headers={
                                'User-Agent': 'BYU-JWT-Python-SDK/1.0 (Python {})'.format(sys.version.replace('\n', ''))})
        response.raise_for_status()
        return response.json()

    def _get_jwks_data(self, jwks_uri):
        """
        Returns the JSON Web Keystore data in JSON format and ttl in seconds
        if no Cache-Control header is found defaults to 1 hour
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
        cache_control = response.headers.get(
            'Cache-Control', 'public max-age=3600').split('=')[1]
        ttl = datetime.now() + timedelta(seconds=cache_control)
        return response.json(), ttl.timestamp()

    def is_valid(self, jwt_to_validate):
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
            self.decode(jwt_to_validate)
            return True
        except Exception:
            return False

    def decode(self, jwt_to_decode):
        """
        >>> ans = decode(_get_test_jwt())
        >>> ans is not None
        True
        """
        x5t = self._extract_x5t_from_jwt(jwt_to_decode)
        pubkeys = self.get_signing_cert()
        decoded_jwt = jwt.decode(jwt_to_decode,
                                 pubkeys[x5t],
                                 verify=True,
                                 issuer=self.jwks_data['issuer'],
                                 leeway=2,
                                 algorithm=['RS256'])
        decoded_jwt = self.add_byu_output_structure(decoded_jwt)
        return decoded_jwt

    def add_byu_output_structure(self, decoded_jwt):
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
        decoded_jwt['byu'] = {
            'client': {
                'byuId': decoded_jwt['http://byu.edu/claims/client_byu_id'],
                'claimSource': decoded_jwt['http://byu.edu/claims/client_claim_source'],
                'netId': decoded_jwt['http://byu.edu/claims/client_net_id'],
                'personId': decoded_jwt['http://byu.edu/claims/client_person_id'],
                'preferredFirstName': decoded_jwt['http://byu.edu/claims/client_preferred_first_name'],
                'prefix': decoded_jwt['http://byu.edu/claims/client_name_prefix'],
                'restOfName': decoded_jwt['http://byu.edu/claims/client_rest_of_name'],
                'sortName': decoded_jwt['http://byu.edu/claims/client_sort_name'],
                'subscriberNetId': decoded_jwt['http://byu.edu/claims/client_subscriber_net_id'],
                'suffix': decoded_jwt['http://byu.edu/claims/client_name_suffix'],
                'surname': decoded_jwt['http://byu.edu/claims/client_surname'],
                'surnamePosition': decoded_jwt['http://byu.edu/claims/client_surname_position']
            }
        }
        decoded_jwt['wso2'] = {
            'apiContext': decoded_jwt['http://wso2.org/claims/apicontext'],
            'application': {
                'id': decoded_jwt['http://wso2.org/claims/applicationid'],
                'name': decoded_jwt['http://wso2.org/claims/applicationname'],
                'tier': decoded_jwt['http://wso2.org/claims/applicationtier'],
            },
            'clientId': decoded_jwt['http://wso2.org/claims/client_id'],
            'endUser': decoded_jwt['http://wso2.org/claims/enduser'],
            'endUserTenantId': decoded_jwt['http://wso2.org/claims/enduserTenantId'],
            'keyType': decoded_jwt['http://wso2.org/claims/keytype'],
            'subscriber': decoded_jwt['http://wso2.org/claims/subscriber'],
            'tier': decoded_jwt['http://wso2.org/claims/tier'],
            'userType': decoded_jwt['http://wso2.org/claims/usertype'],
            'version': decoded_jwt['http://wso2.org/claims/version'],
        }
        if 'http://byu.edu/claims/resourceowner_person_id' in decoded_jwt:
            decoded_jwt['byu']['webresCheck'] = {
                'byuId': decoded_jwt['http://byu.edu/claims/resourceowner_byu_id'],
                'netId': decoded_jwt['http://byu.edu/claims/resourceowner_net_id'],
                'personId': decoded_jwt['http://byu.edu/claims/resourceowner_person_id'],
            }
            decoded_jwt['byu']['resourceOwner'] = {
                'byuId': decoded_jwt['http://byu.edu/claims/resourceowner_byu_id'],
                'netId': decoded_jwt['http://byu.edu/claims/resourceowner_net_id'],
                'personId': decoded_jwt['http://byu.edu/claims/resourceowner_person_id'],
                'preferredFirstName': decoded_jwt['http://byu.edu/claims/resourceowner_preferred_first_name'],
                'prefix': decoded_jwt['http://byu.edu/claims/resourceowner_prefix'],
                'restOfName': decoded_jwt['http://byu.edu/claims/resourceowner_rest_of_name'],
                'sortName': decoded_jwt['http://byu.edu/claims/resourceowner_sort_name'],
                'suffix': decoded_jwt['http://byu.edu/claims/resourceowner_suffix'],
                'surname': decoded_jwt['http://byu.edu/claims/resourceowner_surname'],
                'surnamePosition': decoded_jwt['http://byu.edu/claims/resourceowner_surname_position'],
            }
        else:
            decoded_jwt['byu']['webresCheck'] = {
                'byuId': decoded_jwt['http://byu.edu/claims/client_byu_id'],
                'netId': decoded_jwt['http://byu.edu/claims/client_net_id'],
                'personId': decoded_jwt['http://byu.edu/claims/client_person_id']
            }
        return decoded_jwt
