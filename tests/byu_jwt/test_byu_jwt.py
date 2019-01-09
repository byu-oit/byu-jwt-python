import datetime
from unittest.mock import patch

import byu_jwt
import requests
import pytest
import jwt

from .ref import JWKS, JWT, X5T


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


def test_header():
    assert byu_jwt.JWT_HEADER == 'X-JWT-Assertion'
    assert byu_jwt.BYU_JWT_HEADER_ORIGINAL == 'X-JWT-Assertion-Original'


def test_get_signing_cert():
    byujwt = byu_jwt.JWT_Handler()
    assert byujwt.get_signing_cert()


def test_extract_public_keys():
    byujwt = byu_jwt.JWT_Handler()
    key_set = byujwt._extract_public_keys(JWKS)
    assert key_set


def test_extract_x5t_from_JWT_Handler():
    assert X5T == byu_jwt.extract_x5t_from_jwt(JWT)


def test_get_wellknown_data():
    byujwt = byu_jwt.JWT_Handler()
    well_known = byujwt._get_wellknown_data()
    assert 'jwks_uri' in well_known


def test_get_jwks_data():
    byujwt = byu_jwt.JWT_Handler()
    wellknown = byujwt._get_wellknown_data()
    r, ttl = byujwt._get_jwks_data(wellknown['jwks_uri'])
    assert r == JWKS
    assert ttl == expected_ttl()


def test_is_valid():
    byujwt = byu_jwt.JWT_Handler()
    assert not byujwt.is_valid(JWT)


def test_decode():
    byujwt = byu_jwt.JWT_Handler()
    decoded_jwt = byujwt.decode(JWT, verify=False)
    assert decoded_jwt


@patch('byu_jwt.requests.get')
def test_get_wellknown_data_exception(mock_requests):
    mock_requests.side_effect = requests.exceptions.HTTPError()
    byujwt = byu_jwt.JWT_Handler()
    with pytest.raises(byu_jwt.exceptions.JWTHandlerError):
        byujwt._get_wellknown_data()


@patch('byu_jwt.requests.get')
def test_get_jwks_data_exception(mock_requests):
    mock_requests.side_effect = requests.exceptions.ConnectionError()
    byujwt = byu_jwt.JWT_Handler()
    with pytest.raises(byu_jwt.exceptions.JWTHandlerError):
        byujwt._get_jwks_data('foo')


@patch('byu_jwt.jwt.decode')
def test_decode_jwt_exception(mock_decode):
    mock_decode.side_effect = jwt.exceptions.ExpiredSignatureError()
    byujwt = byu_jwt.JWT_Handler()
    with pytest.raises(byu_jwt.exceptions.JWTVerifyError):
        byujwt.decode("foo")


@patch('byu_jwt.requests.get')
@patch('byu_jwt.extract_x5t_from_jwt')
def test_decode_handler_exception(mock_extract, mock_requests):
    mock_extract.return_value = 'bar'
    mock_requests.side_effect = byu_jwt.exceptions.JWTHandlerError()
    byujwt2 = byu_jwt.JWT_Handler()
    with pytest.raises(byu_jwt.exceptions.JWTHandlerError):
        byujwt2.decode("foo")
