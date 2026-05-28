from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from jose import jwt
from datetime import datetime, timedelta, UTC
import secrets

app = FastAPI()

SECRET_KEY = "super-secret-key"
ALGORITHM = "HS256"

# Fake user database
users = {
    "alice": "password123",
    "bob": "bobpass"
}

# Temporary authorization code storage
auth_codes = {}

# Registered client apps
clients = {
    "myclient": {
        "client_secret": "client-secret-123"
    }
}

# ---------------------------------------------------
# LOGIN PAGE
# ---------------------------------------------------

@app.get("/login", response_class=HTMLResponse)
async def login_page(
    client_id: str,
    redirect_uri: str
):

    return f"""
    <html>
    <body>

        <h1>Identity Provider Login</h1>

        <form method="post" action="/login">

            <input type="hidden"
                   name="client_id"
                   value="{client_id}" />

            <input type="hidden"
                   name="redirect_uri"
                   value="{redirect_uri}" />

            <div>
                Username:
                <input name="username" />
            </div>

            <div>
                Password:
                <input name="password"
                       type="password" />
            </div>

            <button type="submit">
                Login
            </button>

        </form>

    </body>
    </html>
    """

# ---------------------------------------------------
# HANDLE LOGIN
# ---------------------------------------------------

@app.post("/login")
async def handle_login(
    username: str = Form(...),
    password: str = Form(...),
    client_id: str = Form(...),
    redirect_uri: str = Form(...)
):

    if users.get(username) != password:
        raise HTTPException(401, "Invalid credentials")

    # Generate authorization code
    code = secrets.token_hex(16)

    auth_codes[code] = {
        "username": username,
        "expires_at": datetime.now(UTC) + timedelta(minutes=5)
    }

    # Redirect BACK to client app
    redirect_url = (
        f"{redirect_uri}?code={code}"
    )

    return RedirectResponse(
        redirect_url,
        status_code=302
    )

# ---------------------------------------------------
# TOKEN EXCHANGE ENDPOINT
# ---------------------------------------------------

@app.post("/token")
async def token(
    code: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...)
):

    client = clients.get(client_id)

    if not client:
        raise HTTPException(401, "Invalid client")

    if client["client_secret"] != client_secret:
        raise HTTPException(401, "Invalid client secret")

    code_data = auth_codes.get(code)

    if not code_data:
        raise HTTPException(401, "Invalid code")

    if datetime.now(UTC) > code_data["expires_at"]:
        raise HTTPException(401, "Code expired")

    username = code_data["username"]

    # Remove used code
    del auth_codes[code]

    access_token = jwt.encode(
        {
            "sub": username,
            "exp": datetime.now(UTC) + timedelta(minutes=15)
        },
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }