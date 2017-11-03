# byu-jwt-python
A python JWT validator that does all the BYU specific stuff as well.

# Installation
`pip install byu_jwt`

## API

### How to Validate a JWT

```
import byu_jwt
try:
    byu_jwt.decode(jwt_to_validate)
    # valid JWT
except Exception:
    # invalid JWT
```

### JWT Header Names

BYU's API Manager creates an HTTP header that contains a signed [JWT](https://jwt.io/). The names of the designed BYU signed headers can be referenced here for lookup convenience.

### BYU_JWT_HEADER_CURRENT

The property containing the name of the HTTP header that contains the BYU signed JWT sent directly from BYU's API Manager.

Value is X-JWT-Assertion.

Example

```
import byu_jwt
current_jwt_header = byu_jwt.BYU_JWT_HEADER_CURRENT
```

### BYU_JWT_HEADER_ORIGINAL

The property containing the name of the HTTP header that contains the BYU signed JWT forwarded on from a service that received the BYU signed JWT sent directly from BYU's API Manager.

Value is X-JWT-Assertion-Original.

Example

```
import byu_jwt
original_jwt_header = byu_jwt.BYU_JWT_HEADER_ORIGINAL
```

## Testing
To run the integration tests do the following:

You will need a file named ~/.byu/byu-jwt-python.yaml with the following contents. Get your info at https://api.byu.edu/store/site/pages/subscriptions.jag
```
client_id: <your WSO2 application's Consumer Key>
client_secret: <your WSO2 application's Consumer Secret>
```

Make sure you have python and python3 installed on your system, then install virtualenv in whatever way you install python modules (usually `$ pip install virtualenv`).

```
$ virtualenv venv
$ source venv/bin/activate
$ pip install -r requirements
$ pip3 install -r requirements
$ python byu_jwt.py True 
# The 'True' makes the tests run in verbose mode.  
# Leaving it off will run the tests silently and they will only print info if any tests fail.
$ python3 byu_jwt.py True
$ deactivate # to get out of the virtualenv
```
