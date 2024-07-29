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
API_AUDIENCE = "https://api.example.com"  # Your API Audience

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
    # Exchange authorization code for access token
    print("data", data)
    print("*" * 100)
    token_response = requests.post(
        f"https://{AUTH0_DOMAIN}/oauth/token",
        json={
            "grant_type": "authorization_code",
            "client_id": data["client_id"],
            "client_secret": data["client_secret"],
            "code": data["code"],
            "redirect_uri": data["redirect_uri"],
            "code_verifier": data["code_verifier"],
        },
    )
    print("token_response", token_response)
    print("*" * 100)
    token_response_json = token_response.json()

    print("token_response_json", token_response_json)
    print("*" * 100)
    
    if "access_token" in token_response_json:
        print("access_token", token_response_json["access_token"])
        response.set_cookie(
            key="access_token",
            value=token_response_json["access_token"],
            httponly=True,
            secure=True,
            samesite="Strict",
        )
    print("*return" * 100)
    return token_response_json

@app.get("/protected")
async def read_protected(request: Request):
    print("request.cookies", request.cookies)
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    payload = verify_token(token)
    return {"message": "You are authorized", "payload": payload}


@app.get("/check-session")
async def check_session(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    # Optionally, you could verify the token here to ensure it's valid
    return {"message": "Session is valid"}

@app.post("/logout")
async def logout(response: Response):
    response.delete_cookie("access_token")
    return {"message": "Logged out successfully"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)