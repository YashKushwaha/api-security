from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from fastapi import FastAPI, Request
from pathlib import Path
from starlette.middleware.sessions import SessionMiddleware
app = FastAPI()
app.add_middleware(
    SessionMiddleware,
    secret_key="some-random-secret"
)

import os
from authlib.integrations.starlette_client import OAuth

templates_dir = os.path.join(os.path.dirname(__file__), "templates")
print('templates_dir => ', templates_dir, os.path.exists(templates_dir))  # Check if the templates directory exists
templates = Jinja2Templates(directory=templates_dir)

oauth = OAuth()

#cred_dir = Path(__file__).parent.parent.parent / "google_client_secret.json"
cred_file = Path(__file__).parents[2] / "google_client_secret.json"

import json

with open(cred_file) as f:
    google_creds = json.load(f)['web']


oauth.register(
    name="google",

    client_id=google_creds["client_id"],

    client_secret=google_creds["client_secret"],

    server_metadata_url=(
        "https://accounts.google.com/"
        ".well-known/openid-configuration"
    ),

    client_kwargs={
        "scope": "openid email profile"
    }
)

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"request": request}
    )

@app.get("/hello", response_class=HTMLResponse)
async def hello(request: Request):

    return "Hello World"

@app.get("/login/google")
async def login_google(request: Request):

    redirect_uri = request.url_for(
        "auth_callback"
    )
    print("REDIRECT URI => ", redirect_uri)
    
    return await oauth.google.authorize_redirect(
        request,
        redirect_uri
    )

@app.get("/auth/google/callback")
async def auth_callback(request: Request):

    token = await oauth.google.authorize_access_token(
        request
    )

    user_info = token["userinfo"]

    return {
        "email": user_info["email"],
        "name": user_info["name"]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=8000)