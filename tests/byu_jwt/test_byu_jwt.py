import datetime
from unittest.mock import patch

import byu_jwt
import requests
import pytest
import jwt

from .ref import JWKS, JWT, X5T


def test_header():
    """Testing for top level constants to be present"""
    assert byu_jwt.JWT_HEADER == 'X-JWT-Assertion'
    assert byu_jwt.BYU_JWT_HEADER_ORIGINAL == 'X-JWT-Assertion-Original'


def test_get_signing_cert():
    """Testing ability to retrieve signing certs"""
    byujwt = byu_jwt.JWT_Handler()
    assert byujwt.get_signing_cert()


def test_extract_public_keys():
    """Attempting to extract public keys from a JWKS"""
    byujwt = byu_jwt.JWT_Handler()
    key_set = byujwt._extract_public_keys(JWKS)
    assert key_set


def test_extract_x5t_from_JWT_Handler():
    """extract an x5t header from JWT"""
    assert X5T == byu_jwt.extract_x5t_from_jwt(JWT)


def test_get_wellknown_data():
    """get well-known data"""
    byujwt = byu_jwt.JWT_Handler()
    well_known = byujwt._get_wellknown_data()
    assert 'jwks_uri' in well_known


def test_get_jwks_data():
    """get jwks data from uri from well-known data"""
    byujwt = byu_jwt.JWT_Handler()
    wellknown = byujwt._get_wellknown_data()
    r, ttl = byujwt._get_jwks_data(wellknown['jwks_uri'])
    assert r == JWKS
    assert ttl


def test_is_valid():
    """check that is_valid returns False for expired JWT"""
    byujwt = byu_jwt.JWT_Handler()
    assert not byujwt.is_valid(JWT)


def test_decode():
    """verify that decode decodes the jwt"""
    byujwt = byu_jwt.JWT_Handler()
    decoded_jwt = byujwt.decode(JWT, verify=False)
    assert decoded_jwt


@patch('byu_jwt.requests.get')
def test_get_wellknown_data_exception(mock_requests):
    """check exception handling if well-knwon fails"""
    mock_requests.side_effect = [requests.exceptions.HTTPError(), requests.exceptions.ConnectionError()]
    byujwt = byu_jwt.JWT_Handler()
    with pytest.raises(byu_jwt.exceptions.JWTHandlerError):
        byujwt._get_wellknown_data()
        byujwt._get_wellknown_data()


@patch('byu_jwt.requests.get')
def test_get_jwks_data_exception(mock_requests):
    """check exception handling getting jwks"""
    mock_requests.side_effect = [requests.exceptions.HTTPError(), requests.exceptions.ConnectionError()]
    byujwt = byu_jwt.JWT_Handler()
    with pytest.raises(byu_jwt.exceptions.JWTHandlerError):
        byujwt._get_jwks_data('foo')
        byujwt._get_jwks_data('foo')


@patch('byu_jwt.jwt.decode')
def test_decode_jwt_exception(mock_decode):
    """check decode exception handling"""
    mock_decode.side_effect = jwt.exceptions.ExpiredSignatureError()
    byujwt = byu_jwt.JWT_Handler()
    with pytest.raises(byu_jwt.exceptions.JWTVerifyError):
        byujwt.decode("foo")


@patch('byu_jwt.requests.get')
@patch('byu_jwt.extract_x5t_from_jwt')
def test_decode_handler_exception(mock_extract, mock_requests):
    """check decode exception handling"""
    mock_extract.return_value = 'bar'
    mock_requests.side_effect = byu_jwt.exceptions.JWTHandlerError()
    byujwt = byu_jwt.JWT_Handler()
    with pytest.raises(byu_jwt.exceptions.JWTHandlerError):
        byujwt.decode("foo")
