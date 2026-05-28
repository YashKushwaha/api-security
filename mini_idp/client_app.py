from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse
from jose import jwt, JWTError
import httpx

app = FastAPI()

CLIENT_ID = "myclient"
CLIENT_SECRET = "client-secret-123"

AUTH_SERVER = "http://localhost:9000"

SECRET_KEY = "super-secret-key"
ALGORITHM = "HS256"

# ---------------------------------------------------
# HOME PAGE
# ---------------------------------------------------

@app.get("/")
async def home():

    return {
        "message":
        "Visit /dashboard"
    }

# ---------------------------------------------------
# PROTECTED DASHBOARD
# ---------------------------------------------------

@app.get("/dashboard")
async def dashboard(request: Request):

    access_token = request.cookies.get(
        "access_token"
    )

    if not access_token:

        redirect_url = (
            f"{AUTH_SERVER}/login"
            f"?client_id={CLIENT_ID}"
            f"&redirect_uri="
            f"http://localhost:8000/callback"
        )

        return RedirectResponse(
            redirect_url,
            status_code=302
        )

    try:

        payload = jwt.decode(
            access_token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

    except JWTError:

        raise HTTPException(
            401,
            "Invalid token"
        )

    return {
        "message":
        f"Welcome {payload['sub']}"
    }

# ---------------------------------------------------
# CALLBACK ENDPOINT
# ---------------------------------------------------

@app.get("/callback")
async def callback(code: str):

    # Exchange authorization code for token

    async with httpx.AsyncClient() as client:

        response = await client.post(
            f"{AUTH_SERVER}/token",
            data={
                "code": code,
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET
            }
        )

    token_data = response.json()

    access_token = token_data["access_token"]

    # Create local session cookie

    response = RedirectResponse(
        "/dashboard",
        status_code=302
    )

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True
    )

    return response