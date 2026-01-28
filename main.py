from fastapi import FastAPI, Request, Response , Depends
import uvicorn
import jwt


from pydantic import BaseModel
from database import collection
from configs import hash_pass_func, generate_token, get_payload, verify_hash_pw , get_token , generate_refresh_token


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
            
            if password_verify:
                Token = generate_token(email, user["_id"])
                res.set_cookie(
                key="access_token",
                value=Token,
                httponly=True,
                secure=False,
                samesite="lax",
                    )
                
                refresh_token = generate_refresh_token(email, user["_id"])
                res.set_cookie(
                key="refresh_token",
                value=refresh_token,
                httponly=True,
                secure=False,
                samesite="lax",
                    )
                
                return "dashboard"
            else:
                return "wrong email or password "
    except Exception as e:
        return {"error": str(e)}
    
    
@app.post("/refresh")
def refresh(req: Request, res: Response):
    try:
        # Client se refresh token lo
        refresh_token = req.cookies.get("refresh_token")
        if not refresh_token:
            return {"error": "refresh token not found, login again"}

        # Validate karo refresh token
        payload = jwt.decode(refresh_token, secret_key, algorithms=[ALGO])

        # Agar valid hai → naya access token generate karo
        new_access_token = generate_token(payload["email"], payload["_id"])
        res.set_cookie(key="access_token", value=new_access_token, httponly=True)

        return {"message": "new access token issued"}

    except jwt.ExpiredSignatureError:
        return {"error": "refresh token expired, login again"}
    except jwt.InvalidTokenError:
        return {"error": "invalid refresh token"}



@app.get("/dashboard")
def dash(payload = Depends(get_token)):
    try:
        if payload:
            return payload
        
    except Exception as e:
        return {"error": str(e)}
    