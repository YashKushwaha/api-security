from fastapi import FastAPI, Depends, HTTPException, status, Response, Request
import secrets
from tinydb import TinyDB, Query
from passlib.context import CryptContext

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

def add_dummy_users_to_db():
    dummy_users = [
        {'username': 'admin', 'pwd': 'admin123'},
        {'username': 'user1', 'pwd': 'user123'}
    ]
    for user in dummy_users:
        if not user_db.search(Query().username == user['username']):
            username=user['username']
            password=user['pwd']
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
     