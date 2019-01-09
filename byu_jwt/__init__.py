# Copyright 2019 Brigham Young University
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
import json
import sys
import time
from datetime import datetime, timedelta

import jwt
import requests

from .exceptions import JWTHandlerError, JWTVerifyError

JWT_HEADER = 'X-JWT-Assertion'
BYU_JWT_HEADER_ORIGINAL = 'X-JWT-Assertion-Original'


def extract_x5t_from_jwt(_jwt):
    return jwt.get_unverified_header(_jwt)['x5t']


class JWT_Handler(object):
    """BYU_JWT Wraps the process of verifing the BYU JWT"""

    def __init__(self, base_url="https://api.byu.edu"):
        self.base_url = base_url
        self.jwks_data = {'pubkeys': {}, 'issuer': {}, 'ttl': 0}
        self.request_headers = {
            'User-Agent': 'BYU-JWT-Python-SDK/2.0 (Python {})'.format(sys.version.replace('\n', ''))}

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
            thumbprint = key['x5t']
            key_set[thumbprint] = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
        return key_set

    def _get_wellknown_data(self):
        url = '{}/.well-known/openid-configuration'.format(self.base_url)
        try:
            response = requests.get(url, headers=self.request_headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise JWTHandlerError("Error getting .well-known data") from e

    def _get_jwks_data(self, jwks_uri):
        try:
            response = requests.get(jwks_uri, headers=self.request_headers)
            response.raise_for_status()
            cache_control = response.headers.get(
                'Cache-Control', 'public max-age=3600').split('=')[1]
            ttl = datetime.now() + timedelta(seconds=int(cache_control))
            return response.json(), int(ttl.timestamp())
        except requests.exceptions.RequestException as e:
            raise JWTHandlerError("Error getting jwks data") from e

    def is_valid(self, jwt_to_validate):
        try:
            self.decode(jwt_to_validate)
            return True
        except Exception:
            return False

    def decode(self, jwt_to_decode, verify=True):
        try:
            x5t = extract_x5t_from_jwt(jwt_to_decode)
            pubkeys = self.get_signing_cert()
            decoded_jwt = jwt.decode(jwt_to_decode,
                                     pubkeys[x5t],
                                     verify=verify,
                                     issuer=self.jwks_data['issuer'],
                                     leeway=2,
                                     algorithms=['RS256'])
            decoded_jwt = self.add_byu_output_structure(decoded_jwt)
            return decoded_jwt
        except jwt.exceptions.PyJWTError as e:
            raise JWTVerifyError("Invalid JWT") from e

    def add_byu_output_structure(self, decoded_jwt):
        decoded_jwt['byu'] = {
            'client': {
                'byuId': decoded_jwt.pop('http://byu.edu/claims/client_byu_id'),
                'claimSource': decoded_jwt.pop('http://byu.edu/claims/client_claim_source'),
                'netId': decoded_jwt.pop('http://byu.edu/claims/client_net_id'),
                'personId': decoded_jwt.pop('http://byu.edu/claims/client_person_id'),
                'preferredFirstName': decoded_jwt.pop('http://byu.edu/claims/client_preferred_first_name'),
                'prefix': decoded_jwt.pop('http://byu.edu/claims/client_name_prefix'),
                'restOfName': decoded_jwt.pop('http://byu.edu/claims/client_rest_of_name'),
                'sortName': decoded_jwt.pop('http://byu.edu/claims/client_sort_name'),
                'subscriberNetId': decoded_jwt.pop('http://byu.edu/claims/client_subscriber_net_id'),
                'suffix': decoded_jwt.pop('http://byu.edu/claims/client_name_suffix'),
                'surname': decoded_jwt.pop('http://byu.edu/claims/client_surname'),
                'surnamePosition': decoded_jwt.pop('http://byu.edu/claims/client_surname_position')
            }
        }
        decoded_jwt['wso2'] = {
            'apiContext': decoded_jwt.pop('http://wso2.org/claims/apicontext'),
            'application': {
                'id': decoded_jwt.pop('http://wso2.org/claims/applicationid'),
                'name': decoded_jwt.pop('http://wso2.org/claims/applicationname'),
                'tier': decoded_jwt.pop('http://wso2.org/claims/applicationtier'),
            },
            'clientId': decoded_jwt.pop('http://wso2.org/claims/client_id'),
            'endUser': decoded_jwt.pop('http://wso2.org/claims/enduser'),
            'endUserTenantId': decoded_jwt.pop('http://wso2.org/claims/enduserTenantId'),
            'keyType': decoded_jwt.pop('http://wso2.org/claims/keytype'),
            'subscriber': decoded_jwt.pop('http://wso2.org/claims/subscriber'),
            'tier': decoded_jwt.pop('http://wso2.org/claims/tier'),
            'userType': decoded_jwt.pop('http://wso2.org/claims/usertype'),
            'version': decoded_jwt.pop('http://wso2.org/claims/version'),
        }
        if 'http://byu.edu/claims/resourceowner_person_id' in decoded_jwt:
            decoded_jwt['byu']['resourceOwner'] = {
                'byuId': decoded_jwt.pop('http://byu.edu/claims/resourceowner_byu_id'),
                'netId': decoded_jwt.pop('http://byu.edu/claims/resourceowner_net_id'),
                'personId': decoded_jwt.pop('http://byu.edu/claims/resourceowner_person_id'),
                'preferredFirstName': decoded_jwt.pop('http://byu.edu/claims/resourceowner_preferred_first_name'),
                'prefix': decoded_jwt.pop('http://byu.edu/claims/resourceowner_prefix'),
                'restOfName': decoded_jwt.pop('http://byu.edu/claims/resourceowner_rest_of_name'),
                'sortName': decoded_jwt.pop('http://byu.edu/claims/resourceowner_sort_name'),
                'suffix': decoded_jwt.pop('http://byu.edu/claims/resourceowner_suffix'),
                'surname': decoded_jwt.pop('http://byu.edu/claims/resourceowner_surname'),
                'surnamePosition': decoded_jwt.pop('http://byu.edu/claims/resourceowner_surname_position'),
            }
        return decoded_jwt
