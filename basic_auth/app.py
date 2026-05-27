from fastapi import FastAPI, Depends, HTTPException, status, Response, Request
import secrets
from tinydb import TinyDB, Query
from passlib.context import CryptContext
from fastapi.responses import JSONResponse

from datetime import datetime, timedelta, UTC

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

database = TinyDB('database.json')
user_db = database.table('users')
user_wise_file_db = database.table('files')

sessions: dict[str, dict] = {}

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

    expires_at = datetime.now(UTC) + timedelta(minutes=SESSION_DURATION_MINUTES)

    session_id = secrets.token_hex(16)
    print('Session ID generated for user:', session_id)
    
    sessions[session_id] = {"username": user.username,"expires": expires_at}
    
    print('Username added to sessions => ', sessions)
    response = JSONResponse(
            content="Log In Successful",
            status_code=200
        )
    
    response.set_cookie(key="session_id", value=session_id, httponly=True,
                        max_age=SESSION_DURATION_MINUTES * 60, expires=SESSION_DURATION_MINUTES * 60,
                        samesite="lax")
    return response

class UploadRequest(BaseModel):
    filename: str

@app.post('/v1/add_file')
async def add_file(upload: UploadRequest, request: Request):
    session_id = request.cookies.get('session_id')
    print('Session ID from cookie => ', session_id)
    if not session_id:
        raise HTTPException(401, "Not logged in")
    print("Sessions => ", sessions)
    session = sessions.get(session_id)
    if not session:
        raise HTTPException(401, "Invalid session")
    
    if datetime.now(UTC) > sessions[session_id]["expires"]:
        sessions.pop(session_id, None)
        raise HTTPException(401, "Session expired")

    user_wise_file_db.insert(dict(username=session['username'], filename=upload.filename))
    return f"File '{upload.filename}' added for user '{session['username']}'"
