import bcrypt
import jwt
from datetime import timedelta, timezone, datetime
from bcrypt import gensalt


secret_key: str = "hello world"
ALGO: str = "HS256"


def hash_pass_func(password):
    hashedPW = bcrypt.hashpw(password.encode("utf-8"), gensalt())
    return hashedPW.decode()


def generate_token(email, _id):

    payload = {
        "email": email,
        "_id": _id,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
    }

    token = jwt.encode(payload, secret_key, algorithm=ALGO)
    return token


def get_payload(token):
    payload = jwt.decode(token, secret_key, algorithms=ALGO)
    return payload


def verify_hash_pw(password, dbpass):
    isvalid = bcrypt.checkpw(password.encode(), dbpass.encode())
    if isvalid:
        return True
    else:
        return False
