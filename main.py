import json
from fastapi import FastAPI, HTTPException, Form, Depends, Request, File, Form, UploadFile
from fastapi.responses import JSONResponse
import boto3
from jose import ExpiredSignatureError, JWTError, jwt
import hmac
import hashlib
import base64
import os
import tempfile
from cognitojwt import jwt_sync
import urllib.request

from dotenv import load_dotenv

from upload_image import upload_image_to_bucket

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
    keys_url = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(COGNITO_REGION, USER_POOL_ID)
    with urllib.request.urlopen(keys_url) as f:
        response = f.read()
    keys = json.loads(response.decode('utf-8'))['keys']
    return keys


# Function to get public key for token validation
def get_public_key(kid: str):
    keys = get_cognito_public_key()
    key = next(key for key in keys if key["kid"] == kid)
    return key


# Function to validate JWT token
# from fastapi import HTTPException
# from jose import ExpiredSignatureError, JWTError, jwt

def validate_token(token: str):
    try:
        header = jwt.get_unverified_header(token)
        kid = header["kid"]  
        public_key = get_public_key(kid)
        if not public_key:
            raise HTTPException(status_code=500, detail="Unable to fetch public key")
        
        payload = jwt.decode(token, public_key, algorithms=["RS256"])
        return payload
    except ExpiredSignatureError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except JWTError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except HTTPException as e:
        raise e
    except Exception:
        raise HTTPException(status_code=500, detail="Internal Server Error")
    

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


@app.post("/confirmed-signup")
async def confirmed_sign_up(request: Request):
    body = await request.body()
    body_str = body.decode("utf-8")
    json_body = json.loads(body_str)
    email = json_body.get('email')
    code = json_body.get('code') 
    cognito_client = boto3.client("cognito-idp", region_name=COGNITO_REGION)

    try:
        secret_hash = get_secret_hash(email, CLIENT_ID, CLIENT_SECRET)
        response = cognito_client.confirm_sign_up(
            ClientId=CLIENT_ID,
            SecretHash=secret_hash,
            Username=email,
            ConfirmationCode=code,
            ForceAliasCreation=True|False,
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
        content={"message": "confirmation successfully", "Responce": response}
    )


@app.post("/initiate-auth")
async def initiate_auth_(request: Request):
    body = await request.body()
    body_str = body.decode("utf-8")
    json_body = json.loads(body_str)
    username = json_body.get('username')
    password = json_body.get('password')
    cognito_client = boto3.client("cognito-idp", region_name=COGNITO_REGION)

    try:
        secret_hash = get_secret_hash(username, CLIENT_ID, CLIENT_SECRET)
        auth_params = {
            'AuthFlow': 'USER_PASSWORD_AUTH',
            'ClientId': CLIENT_ID,
            'AuthParameters': {
                'USERNAME': username,
                'PASSWORD': password,
                'SECRET_HASH': secret_hash  
            }
        }

        response = cognito_client.initiate_auth(**auth_params)

    except cognito_client.exceptions.UsernameExistsException:
        raise HTTPException(status_code=400, detail="Email address already exists")
    except cognito_client.exceptions.InvalidPasswordException:
        raise HTTPException(status_code=400, detail="Invalid password")
    except cognito_client.exceptions.UserLambdaValidationException:
        raise HTTPException(status_code=400, detail="Email address already exists")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return JSONResponse(
        content={"message": "confirmation successfully", "Responce": response}
    )


@app.post('/upload-image')
async def upload_image(request:Request, image: UploadFile = File(...)):
    try:
        access_token = request.headers.get("Authorization")
        if access_token is not None:
            payload = validate_token(access_token)
            if payload  is not None:
                file_name = image.filename
                username = payload['username']
                s3_key = f'{username}/{file_name}'
                with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                    contents = await image.read()
                    temp_file.write(contents)
                    temp_file_path = temp_file.name
                return await upload_image_to_bucket(temp_file_path, s3_key)
        else:
            raise HTTPException(status_code=401, detail="Invalid authorization header")
    except ExpiredSignatureError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except JWTError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except HTTPException as e:
        raise e
    except Exception:
        raise HTTPException(status_code=500, detail="Internal Server Error")

        
@app.post("/decode-jwt")
def decode_jwt(request: Request):
    try:
        access_token = request.headers.get("Authorization")
        if not access_token:
            raise HTTPException(status_code=401, detail="Invalid authorization header")
        payload = validate_token(access_token)
        return {"payload": payload}
    except ExpiredSignatureError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except JWTError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except HTTPException as e:
        raise e
    except Exception:
        raise HTTPException(status_code=500, detail="Internal Server Error")


    