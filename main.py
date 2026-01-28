from fastapi import FastAPI, Request, Response
import uvicorn


from pydantic import BaseModel
from database import collection
from configs import hash_pass_func, generate_token, get_payload, verify_hash_pw


app = FastAPI()


class User(BaseModel):
    name: str
    age: int
    email: str
    password: str


class Login(BaseModel):
    email: str
    password: str


@app.get("/")
async def method_name():
    return "server started"


@app.post("/register")
async def register_route(user: User, res: Response):
    try:
        value = user.model_dump()
        email: str = value["email"]
        user_exists = await collection.find_one({"email": email})
        if not user_exists:
            hashed_password = hash_pass_func(value["password"])

            insert_user = await collection.insert_one(
                {
                    "name": value["name"],
                    "email": value["email"],
                    "password": hashed_password,
                    "age": value["age"],
                }
            )

            user_id = str(insert_user.inserted_id)

            Token = generate_token(value["email"], user_id)

            res.set_cookie(
                key="access_token",
                value=Token,
                httponly=True,
                secure=False,
                samesite="lax",
            )

            return "inserted"
        if user_exists:
            return "user already exist login instead"

    except Exception as e:
        return {"error": str(e)}


@app.get("/gettoken")
def kii(req: Request):
    try:
        token = req.cookies.get("access_token")
        if not token:
            return "token not found"
        payload = get_payload(token)
        return payload
    except Exception as e:
        return {"error": str(e)}


@app.post("/login")
async def login_route(data: Login, res: Response):
    try:
        user_data = data.model_dump()
        email = user_data["email"]
        password = user_data["password"]

        user = await collection.find_one({"email": email})
        if not user:
            return "user do not exist , register instead"
        elif user:
            user["_id"] = str(user["_id"])
            password_verify = verify_hash_pw(password, user["password"])
            Token = generate_token(email, user["_id"])
            res.set_cookie(
                key="access_token",
                value=Token,
                httponly=True,
                secure=False,
                samesite="lax",
            )
            if password_verify:
                return "dashboard"
            else:
                return "wrong email or password "
    except Exception as e:
        return {"error": str(e)}
