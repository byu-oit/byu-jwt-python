# byu-jwt-python
A python JWT validator that does all the BYU specific stuff as well.


You will need a file named ~/.byu/byu-jwt-python.yaml with the following contents. Get your info at https://api.byu.edu/store/site/pages/subscriptions.jag
```
client_id: <your WSO2 application's Consumer Key>
client_secret: <your WSO2 application's Consumer Secret>
```

## API
### JWT Header Names

BYU's API Manager creates an HTTP header that contains a signed [JWT](https://jwt.io/). The names of the designed BYU signed headers can be referenced here for lookup convenience.

### BYU_JWT_HEADER_CURRENT

The property containing the name of the HTTP header that contains the BYU signed JWT sent directly from BYU's API Manager.

Value is X-JWT-Assertion.

Example

The example uses the property to retrieve the header from the request.

```
import byu_jwt
current_jwt_header = byu_jwt.BYU_JWT_HEADER_CURRENT
```

### BYU_JWT_HEADER_ORIGINAL

The property containing the name of the HTTP header that contains the BYU signed JWT forwarded on from a service that received the BYU signed JWT sent directly from BYU's API Manager.

Value is X-JWT-Assertion-Original.

Example

The example uses the property to retrieve the header from the request.

```
import byu_jwt
current_jwt_header = byu_jwt.BYU_JWT_HEADER_ORIGINAL
```
