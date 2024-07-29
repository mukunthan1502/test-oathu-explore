from fastapi import FastAPI, Depends, HTTPException, status, Request, Response
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, jwk, JWTError
from jose.utils import base64url_decode
import requests
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
AUTH0_DOMAIN = "dev-ptqk6ibc8njgm5ty.us.auth0.com"
JWKS_URL = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
ALGORITHMS = ["RS256"]
API_AUDIENCE = "https://api.example.com"
CLIENT_ID = "xmPoVoVk6WrffxGwPhDyOVUB3uhuDqre"
CLIENT_SECRET = "0F0Kn0j_SrecdoUrzHVFgXKWA-qE4BBOxdvDbTrGGllGmVSNgmKyLGVjI7WfaWzT"

# Fetch the JWKS
response = requests.get(JWKS_URL)
jwks = response.json()

def get_public_key(kid):
    key = next((key for key in jwks['keys'] if key['kid'] == kid), None)
    if not key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Public key not found")
    return jwk.construct(key)

def add_padding(base64_string):
    """Add padding to a base64 string if necessary."""
    return base64_string + '=' * (4 - len(base64_string) % 4)

def verify_token(token: str):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        headers = jwt.get_unverified_headers(token)
        kid = headers['kid']
        key = get_public_key(kid)
        message, encoded_signature = token.rsplit('.', 1)
        encoded_signature = add_padding(encoded_signature)
        decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
        if not key.verify(message.encode('utf-8'), decoded_signature):
            raise credentials_exception
        payload = jwt.decode(token, key, algorithms=ALGORITHMS, audience=API_AUDIENCE)
        return payload
    except JWTError as e:
        print(f"JWT Error: {e}")
        raise credentials_exception
    except Exception as e:
        print(f"Error: {e}")
        raise credentials_exception

@app.post("/token")
async def token_endpoint(request: Request, response: Response):
    data = await request.json()
    token_response = requests.post(
        f"https://{AUTH0_DOMAIN}/oauth/token",
        json={
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code": data.get("code"),
            "redirect_uri": data.get("redirect_uri"),
            "code_verifier": data.get("code_verifier"),
        },
    )
    token_response_json = token_response.json()

    print("token_response_json", token_response_json)
    
    if "access_token" in token_response_json:
        response.set_cookie(
            key="access_token",
            value=token_response_json["access_token"],
            httponly=True,
            secure=True,
            samesite="Strict",
        )
    if "refresh_token" in token_response_json:
        response.set_cookie(
            key="refresh_token",
            value=token_response_json["refresh_token"],
            httponly=True,
            secure=True,
            samesite="Strict",
        )
    return token_response_json

@app.post("/refresh-token")
async def refresh_token(request: Request, response: Response):
    print("refresh_token", request.cookies.get("refresh_token"))
    data = await request.json()
    # refresh_token = data.get("refresh_token")
    refresh_token = request.cookies.get("refresh_token")

    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token not found")

    token_response = requests.post(
        f"https://{AUTH0_DOMAIN}/oauth/token",
        json={
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "refresh_token": refresh_token,
        }
    )
    token_response_json = token_response.json()
    if "access_token" in token_response_json:
        response.set_cookie(
            key="access_token",
            value=token_response_json["access_token"],
            httponly=True,
            secure=True,
            samesite="Strict",
        )
    if "refresh_token" in token_response_json:
        response.set_cookie(
            key="refresh_token",
            value=token_response_json["refresh_token"],
            httponly=True,
            secure=True,
            samesite="Strict",
        )
    return token_response_json

# @app.get("/protected")
# async def read_protected(request: Request):
#     token = request.cookies.get("access_token")
#     if not token:
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
#     payload = verify_token(token)
#     return {"message": "You are authorized", "payload": payload}


def refresh_access_token(refresh_token: str):
    token_response = requests.post(
        f"https://{AUTH0_DOMAIN}/oauth/token",
        json={
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "refresh_token": refresh_token,
        }
    )
    token_response_json = token_response.json()
    print("token_response_json", token_response_json)
    if "access_token" in token_response_json:
        return token_response_json["access_token"], token_response_json.get("refresh_token")
    else:
        raise HTTPException(status_code=401, detail="Unable to refresh token")


@app.get("/protected")
async def read_protected(request: Request, response: Response):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    try:
        payload = verify_token(token)
        print("payload", payload)
    except HTTPException:
        # Token is expired or invalid, try to refresh it
        refresh_token = request.cookies.get("refresh_token")
        print("refresh_token", refresh_token)
        if not refresh_token:
            response.delete_cookie("access_token")
            response.delete_cookie("refresh_token")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired, please login again")
        try:
            new_access_token, new_refresh_token = refresh_access_token(refresh_token)
            print("after refresh")
            response.set_cookie(
                key="access_token",
                value=new_access_token,
                httponly=True,
                secure=True,
                samesite="Strict",
            )
            if new_refresh_token:
                response.set_cookie(
                    key="refresh_token",
                    value=new_refresh_token,
                    httponly=True,
                    secure=True,
                    samesite="Strict",
                )
            
            print("new_access_token", new_access_token)
            print("new_refresh_token", new_refresh_token)

            payload = verify_token(new_access_token)
        except HTTPException:
            print("Unable to refresh token")
            response.delete_cookie("access_token")
            response.delete_cookie("refresh_token")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired, please login again")
    return {"message": "You are authorized", "payload": payload}




@app.get("/check-session")
async def check_session(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    return {"message": "Session is valid"}

@app.post("/logout")
async def logout(response: Response):
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    return {"message": "Logged out successfully"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
