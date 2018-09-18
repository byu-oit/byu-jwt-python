import pytest
from .ref import JWKS, X5C, X5T, JWT
from byu_jwt import BYU_JWT


@pytest.mark.skip()
def test_get_signing_cert():
    assert False


@pytest.mark.skip()
def test_extract_public_keys():
    # TODO Need to unit test as this is undocumented feature of pyjwt library
    assert False


def test_generate_x5t_from_x5c():
    assert X5T == BYU_JWT.generate_x5t_from_x5c(X5C)


def test_extract_x5t_from_jwt():
    assert X5T == BYU_JWT.extract_x5t_from_jwt(JWT)


@pytest.mark.skip()
def test_get_wellknown_data():
    """
    Returns the wellknown URL's JSON
    >>> isinstance(get_wellknown_data(), dict)
    True
    """
    assert False


@pytest.mark.skip()
def test_get_jwks_data():
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
    assert False


@pytest.mark.skip()
def test_is_valid():
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
    assert False


@pytest.mark.skip()
def test_decode():
    """
    >>> ans = decode(_get_test_jwt())
    >>> ans is not None
    True
    """
    assert False


@pytest.mark.skip()
def test_add_byu_output_structure():
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
    assert False
