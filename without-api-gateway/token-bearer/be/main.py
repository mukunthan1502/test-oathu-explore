from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, jwk, JWTError
from jose.utils import base64url_decode
import requests
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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

# OAuth2PasswordBearer gets the token from the request header
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")



def get_public_key(kid):
    print("kid", kid)
    key = next((key for key in jwks['keys'] if key['kid'] == kid), None)
    print("key", key)
    if not key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Public key not found")
    return jwk.construct(key)


def add_padding(base64_string):
    """Add padding to a base64 string if necessary."""
    return base64_string + '=' * (4 - len(base64_string) % 4)

def verify_token(token: str):
    print("verify_token", token)
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
        print("*decoded_signature"*50)
        if not key.verify(message.encode('utf-8'), decoded_signature):
            raise credentials_exception
        print("error"*50)
        # Decode token with verification
        # payload = jwt.decode(token, key, algorithms=ALGORITHMS)
        payload = jwt.decode(token, key, algorithms=ALGORITHMS, audience=API_AUDIENCE)

        print("payload", payload)
        return payload
    except JWTError as e:
        print(f"JWT Error: {e}")
        raise credentials_exception
    except Exception as e:
        print(f"Error: {e}")
        raise credentials_exception

@app.get("/protected")
async def read_protected(token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    return {"message": "You are authorized", "payload": {'aaa': 1}}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)