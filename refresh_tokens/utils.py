from datetime import datetime, timedelta, UTC
from jose import jwt, JWTError
# JOSE stands for Javascript Object Signing and Encryption
import secrets

SECRET_KEY = "super-secret-key-change-this"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Set the multipier to 1 instead of 60 so that our token expires in 30 seconds instead of 30 mins 
SECONDS_IN_A_MINUTE= 1

def create_refresh_token():
    return secrets.token_hex(32)

def create_access_token(data: dict):

    to_encode = data.copy()

    expire = datetime.now(UTC) + timedelta(
        seconds=ACCESS_TOKEN_EXPIRE_MINUTES*SECONDS_IN_A_MINUTE
    )
    # Note: jwt expects the "exp" claim to be a Unix timestamp (number of seconds since Jan 1, 1970), so it will convert 1970-01-01 00:00:00 UTC into 1779891575
    to_encode.update({
        "exp": expire
    })

    encoded_jwt = jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    return encoded_jwt