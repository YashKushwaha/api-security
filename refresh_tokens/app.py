from fastapi import FastAPI, Depends, HTTPException, status, Response, Request
import secrets
from tinydb import TinyDB, Query
from tinydb.storages import JSONStorage

from passlib.context import CryptContext
from fastapi.responses import JSONResponse
from jose import jwt, JWTError
from datetime import datetime, timedelta, UTC

from .utils import create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES, SECRET_KEY, ALGORITHM, create_refresh_token, SECONDS_IN_A_MINUTE


SESSION_DURATION_MINUTES = 1 # Make it 1 minute for testing purposes

pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto"
)

from pydantic import BaseModel

class User(BaseModel):
    username: str
    password: str

app = FastAPI()

database = TinyDB('database_refresh_tokens.json',storage=JSONStorage, indent=2)
user_db = database.table('users')
user_wise_file_db = database.table('files')
refresh_token_db = database.table("refresh_tokens")

REFRESH_TOKEN_EXPIRE_DAYS = 7
## Cookie settings are in seconds thus we need a multiply day value with 24*60*60
## For testing purpose we set the multipier at 10 so that refresh token expires in 70 secs instead of 7 days

SECONDS_IN_A_DAY = 10

# No need for sessions dict in JWT based auth as we are not storing any session data on server side. The token itself contains all the necessary information and is stateless.
#sessions: dict[str, dict] = {}

def add_dummy_users_to_db():
    dummy_users = [
        {'username': 'admin', 'password': 'admin123'},
        {'username': 'user1', 'password': 'user123'},
        {'username': 'string', 'password': 'string'},
    ]
    for user in dummy_users:
        if not user_db.search(Query().username == user['username']):
            username=user['username']
            password=user['password']
            password=pwd_context.hash(password)
            
            user = User(
                username=username,
                password=password
            )
            user_db.insert(user.model_dump())


import os
print("Current working directory:", os.getcwd())

add_dummy_users_to_db()

def user_exists(username):
    return user_db.search(Query().username == username)

@app.post('/v1/sign_up', status_code=status.HTTP_201_CREATED)
async def sign_up(user: User):
    if user_exists(user.username):
        raise HTTPException(401, "user already exists")

    password = pwd_context.hash(user.password)
    user_db.insert(dict(username=user.username, password=password))
    return f"User added: {user.username}"

@app.post('/v1/login') 
async def login(user: User, response: Response):
    user_data = user_exists(user.username)
    print('user_data => ', user_data)
    # Check if user exists in first place
    if not user_data:
        raise HTTPException(401, "User not found")
    
    # Check if password matches
    if not pwd_context.verify(user.password, user_data[0]["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")


    response = JSONResponse(
            content="Log In Successful",
            status_code=200
        )
    
    token = create_access_token(data={"sub": user.username})
    print("JWT Token created, Length => ", len(token))
    refresh_token = create_refresh_token()
    refresh_token_db.insert({
        "refresh_token": refresh_token,
        "username": user.username,
        "expires_at": (
            datetime.now(UTC) + timedelta(days=7)
        ).timestamp()
    })

    response.set_cookie(key="access_token", value=token, httponly=True,
                        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * SECONDS_IN_A_MINUTE, expires=ACCESS_TOKEN_EXPIRE_MINUTES * SECONDS_IN_A_MINUTE,
                        samesite="lax")
    response.set_cookie(key="refresh_token", value=refresh_token, httponly=True,
                        max_age=REFRESH_TOKEN_EXPIRE_DAYS * SECONDS_IN_A_DAY, expires=REFRESH_TOKEN_EXPIRE_DAYS * SECONDS_IN_A_DAY,
                        samesite="lax")
    return response

class UploadRequest(BaseModel):
    filename: str

def decode_payload(request: Request):
    access_token = request.cookies.get('access_token')
    if not access_token:
        raise HTTPException(401, "Not logged in")
    
    print(f'Len token: {len(access_token)}  {access_token[:5]}...{access_token[-5:]}')

    try:

        payload = jwt.decode(
            access_token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )
        print("Decoded payload from token => ", payload)
        username = payload.get("sub")

        if not username:
            raise HTTPException(401, "Invalid token")

    except JWTError:
        raise HTTPException(401, "Invalid or expired token")
    return payload

@app.post('/v1/add_file')
async def add_file(upload: UploadRequest, payload = Depends(decode_payload)):
    username = payload.get("sub")
    exp = payload.get("exp")
    if exp and datetime.now(UTC) > datetime.fromtimestamp(exp, tz=UTC):
        raise HTTPException(401, "Token expired")


    FileQuery = Query()

    existing_record = user_wise_file_db.search(
        (FileQuery.username == username) &
        (FileQuery.filename == upload.filename)
    )

    # overwrite existing record
    if existing_record:

        user_wise_file_db.update(
            dict(
                username=username,
                filename=upload.filename),
            (FileQuery.username == username) &
            (FileQuery.filename == upload.filename)
        )

        return {
            "status": "updated",
            "message": f"Existing file entry overwritten for '{username}'",
            "filename": upload.filename
        }
    # fresh insert
    user_wise_file_db.insert(dict(username=username,filename=upload.filename))

    return {
        "status": "created",
        "message": f"New file entry created for '{username}'",
        "filename": upload.filename
    }

@app.post("/v1/refresh")
async def refresh(request: Request):

    refresh_token = request.cookies.get("refresh_token")
    print('refresh_token => ', refresh_token)

    if not refresh_token:
        raise HTTPException(401, "Missing refresh token")
    
    token_data = refresh_token_db.search(
        Query().refresh_token == refresh_token
    )

    if not token_data:
        raise HTTPException(401, "Invalid refresh token")
    
    token_data = token_data[0]

    expires_at = datetime.fromtimestamp(
        token_data["expires_at"],
        tz=UTC
    )

    if datetime.now(UTC) > expires_at:
        raise HTTPException(401, "Refresh token expired")
    
    username = token_data["username"]

    new_access_token = create_access_token(
        data={"sub": username}
    )

    response = JSONResponse(
    content="Access token refreshed"
)

    response.set_cookie(
        key="access_token",
        value=new_access_token,
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax"
    )

    return response