import datetime
from .ref import JWKS, X5T, JWT
import byu_jwt


def expected_ttl():
    now = datetime.datetime.utcnow()
    expires = None
    if now.hour < 12:
        expires = now.replace(
            hour=12, minute=0, second=0, microsecond=0)
    else:
        tomorrow = now + datetime.timedelta(days=1)
        expires = tomorrow.replace(
            hour=12, minute=0, second=0, microsecond=0)
    cache_control = round((expires - now).total_seconds())
    ttl = datetime.datetime.now() + datetime.timedelta(seconds=cache_control)
    return int(ttl.timestamp())


def test_get_signing_cert():
    byujwt = byu_jwt.JWT()
    assert byujwt.get_signing_cert()


def test_extract_public_keys():
    byujwt = byu_jwt.JWT()
    key_set = byujwt._extract_public_keys(JWKS)
    assert key_set


def test_extract_x5t_from_jwt():
    assert X5T == byu_jwt.JWT.extract_x5t_from_jwt(JWT)


def test_get_wellknown_data():
    byujwt = byu_jwt.JWT()
    well_known = byujwt._get_wellknown_data()
    assert 'jwks_uri' in well_known


def test_get_jwks_data():
    byujwt = byu_jwt.JWT()
    wellknown = byujwt._get_wellknown_data()
    r, ttl = byujwt._get_jwks_data(wellknown['jwks_uri'])
    assert r == JWKS
    assert ttl == expected_ttl()


def test_is_valid():
    byujwt = byu_jwt.JWT()
    assert not byujwt.is_valid(JWT)


def test_decode():
    byujwt = byu_jwt.JWT()
    decoded_jwt = byujwt.decode(JWT, verify=False)
    assert decoded_jwt
