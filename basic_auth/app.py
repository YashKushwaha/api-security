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

########################################################
"""
In the previous apporaches the endpoint was managing the security
Now we move to framework injects authenticated identity
"""

def get_current_user(request:Request):
    session_id = request.cookies.get('session_id')

    if not session_id:
        # If there is no session id that means user in not logged in
        raise HTTPException(401, "Not logged in")
    
    username = sessions.get(session_id)

    if not username:
        """
        Happens when say user logged out so we deleted the session form our state but browser is still sending the old cookie. e.g employee badge deactivated.
        Server restart - If session was in memory then after restart / crash all the session will be gone. That's why we use Redis, databases etc
        Session Expired - Not implemented currently but if implemented expired sessions are removed automatically. e.g. hotel keycard expires after checkout time.
        Deployment to another server - Load balancer may route request to server B, but the state was created in Server B.
        Removed during automatic session cleanup
        Bug in session storage
        Multiple tabs used -> Logged in from tab A, logged out from Tab B but still trying to user Tab A

        SECURITY RISKS -
        - Session guessing - someone tries random session IDs that's why secrets.token_hex(16) is important
        - Stolen old session
        - Tampered cookie - hacker manually edits the cookie
        """
        raise HTTPException(401, "Invalid session")
    
    return username

@app.get("/v2/profile")
def profile(username: str = Depends(get_current_user)):

    return {
        "logged_in_as": username
    }

@app.get("/v2/myfiles/{file_name}")
def get_files(
    file_name: str,
    username: str = Depends(get_current_user)
):
    return {
        "user": username,
        "file": file_name
    }