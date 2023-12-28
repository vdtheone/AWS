import json
from fastapi import FastAPI, HTTPException, Form, Depends, Request
from fastapi.responses import JSONResponse
import boto3
from jose import jwt
import hmac
import hashlib
import base64
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()


COGNITO_REGION = os.environ.get("COGNITO_REGION")
USER_POOL_ID = os.environ.get("USER_POOL_ID")
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")


def get_secret_hash(username, client_id, client_secret):
    msg = username + client_id
    dig = hmac.new(
        str(client_secret).encode("utf-8"),
        msg=str(msg).encode("utf-8"),
        digestmod=hashlib.sha256,
    ).digest()
    return base64.b64encode(dig).decode()


# Function to get Cognito public key for token validation
def get_cognito_public_key():
    cognito_client = boto3.client("cognito-idp", region_name=COGNITO_REGION)
    response = cognito_client.get_user_pool(UserPoolId=USER_POOL_ID)
    keys = response["UserPool"]["VerificationMessageTemplate"]["EmailMessageByLink"]
    return keys


# Function to get public key for token validation
def get_public_key(kid: str):
    keys = get_cognito_public_key()
    key = next(key for key in keys if key["KeyId"] == kid)
    return jwt.algorithms.RSAAlgorithm.from_jwk(key)


# Function to validate JWT token
def validate_token(token: str):
    try:
        payload = jwt.decode(token, get_public_key, algorithms=["RS256"])
        return payload
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# Registration endpoint
@app.post("/register")
async def register(
    email: str = Form(...),
    password: str = Form(...),
):
    # Register the user in Cognito
    cognito_client = boto3.client("cognito-idp", region_name=COGNITO_REGION)
    try:
        secret_hash = get_secret_hash(email, CLIENT_ID, CLIENT_SECRET)
        resp = cognito_client.sign_up(
            ClientId=CLIENT_ID,
            SecretHash=secret_hash,
            Username=email,  # Use the email as the username
            Password=password,
            UserAttributes=[
                {"Name": "email", "Value": email},
            ],
        )

    except cognito_client.exceptions.UsernameExistsException:
        raise HTTPException(status_code=400, detail="Email address already exists")
    except cognito_client.exceptions.InvalidPasswordException:
        raise HTTPException(status_code=400, detail="Invalid password")
    except cognito_client.exceptions.UserLambdaValidationException:
        raise HTTPException(status_code=400, detail="Email address already exists")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return JSONResponse(
        content={"message": "User registered successfully", "Responce": resp}
    )




    