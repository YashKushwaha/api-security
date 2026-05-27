from datetime import datetime, timedelta, UTC
from jose import jwt, JWTError
# JOSE stands for Javascript Object Signing and Encryption

SECRET_KEY = "super-secret-key-change-this"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1

def create_access_token(data: dict):

    to_encode = data.copy()

    expire = datetime.now(UTC) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
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