from fastapi import FastAPI, Depends, HTTPException, status, Response, Request
import secrets

app = FastAPI()

db = {'admin': {"pwd": "admin123"},
      'user1': {"pwd": "user123"}}

sessions = {}

def auth(username, password):
    return db[username]["pwd"] == password

@app.post("/login_v1")
def login(username: str, password: str):
    if auth(username, password):
        return True
    return False

@app.post("/login_v2")
def login(username: str, password: str, response: Response):
    user = db.get(username)

    if not user or user["pwd"] != password:
        raise HTTPException(401, "Invalid credentials")

    session_id = secrets.token_hex(16)
    print('Session ID generated for user:', session_id)
    sessions[session_id] = username

    response.set_cookie(key="session_id", value=session_id, httponly=True)
    return {
        "message": "Logged in"
    }


@app.get("/myfiles/{file_name}")
def get_files(file_name):
        return f"This is file: {file_name}"

@app.post("/logout")
def logout(request: Request, response: Response):

    session_id = request.cookies.get("session_id")

    if session_id:
        sessions.pop(session_id, None)

    response.delete_cookie("session_id")

    return {"message": "Logged out"}

@app.get("/profile")
def profile(request: Request):

    session_id = request.cookies.get("session_id")

    if not session_id:
        raise HTTPException(401, "Not logged in")

    username = sessions.get(session_id)

    if not username:
        raise HTTPException(401, "Invalid session")

    return {
        "logged_in_as": username
    }