# byu-jwt-python
A python JWT validator that does all the BYU specific stuff as well as handle caching well-known and cert fetching

# Installation
`pip install byu_jwt`

## API

---
**Note: It is important to declare the handler at a global level. This allows the caching of the well-known data as well as using the cache-control headers on the certificates only re-fetching those when cache-control has timed out. Reinitializing the class object will negate any benefit of the caching**

---
Instantiate the class and reuse the object to utilize caching:
```python
import byu_jwt
byujwt = byu_jwt.JWT_Handler()
```

### Check only if JWT is valid
```python
assert byujwt.is_valid(jwt_to_validate)
```

### Decode JWT and Check validity
```python
try:
    jwt = byujwt.decode(jwt_to_validate)
    return f"Hello, {jwt['preferredFirstName']}"
except byu_jwt.exceptions.JWTVerifyError as ex_info:
    return "Invalid JWT"
except byu_jwt.exceptions.JWTHandlerError as ex_info:
    return "Error attempting to verify the jwt"
```

### JWT Header Names

BYU's API Manager creates an HTTP header that contains a signed [JWT](https://jwt.io/). The names of the designed BYU signed headers can be referenced here for lookup convenience.

### BYU_JWT_HEADER_CURRENT

The property containing the name of the HTTP header that contains the BYU signed JWT sent directly from BYU's API Manager.

Value is X-JWT-Assertion.

Example

```python
current_jwt_header = byu_jwt.JWT_HEADER
```

### BYU_JWT_HEADER_ORIGINAL

The property containing the name of the HTTP header that contains the BYU signed JWT forwarded on from a service that received the BYU signed JWT sent directly from BYU's API Manager.

Value is X-JWT-Assertion-Original.

Example

```python
original_jwt_header = byu_jwt.JWT_HEADER_ORIGINAL
```

### Example Python Lambda function that makes use of caching
```python
import byu_jwt

byujwt = byu_jwt.JWT_Handler()

def handler(event, context):
    jwt_to_decode = event['headers'][byu_jwt.JWT_HEADER]
    try:
        jwt = byujwt.decode(jwt_to_validate)
        return {'statusCode': 200, 'body': f'Hello, {jwt["preferredFirstName"]}'}
    except byu_jwt.exceptions.JWTVerifyError as ex_info:
        return {'statusCode': 403, 'body': "Invalid JWT"}
    except byu_jwt.exceptions.JWTHandlerError as ex_info:
        return {'statusCode': 500, 'body': "Error attempting to verify the jwt"}
```


### Example Decoded JWT Structure
```json
{
  "iss": "https://api.byu.edu",
  "exp": 1545425710,
  "byu": {
    "client": {
      "byuId": "",
      "claimSource": "",
      "netId": "",
      "personId": "",
      "preferredFirstName": "",
      "prefix": "",
      "restOfName": "",
      "sortName": "",
      "subscriberNetId": "",
      "suffix": "",
      "surname": "",
      "surnamePosition": ""
    },
    "resourceOwner": {
      "byuId": "",
      "netId": "",
      "personId": "",
      "preferredFirstName": "",
      "prefix": "",
      "restOfName": "",
      "sortName": "",
      "suffix": "",
      "surname": "",
      "surnamePosition": ""
    }
  },
  "wso2": {
    "apiContext": "",
    "application": {
      "id": "",
      "name": "",
      "tier": ""
    },
    "clientId": "",
    "endUser": "",
    "endUserTenantId": "",
    "keyType": "",
    "subscriber": "",
    "tier": "",
    "userType": "",
    "version": ""
  }
}
```