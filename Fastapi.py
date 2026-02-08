import os
import shutil
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, File, UploadFile, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr

# CONFIG
SECRET_KEY = "SAB_SE_BADI_CHABI_123"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

UPLOAD_DIR = "static/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = FastAPI(
    title="Professional FastAPI Project",
    version="1.0.0"
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# DATABASE
users_db = {}
items_db = []

# MODELS
class User(BaseModel):
    username: str
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    role: str = "User"

class UserCreate(BaseModel):
    username: str
    password: str
    email: EmailStr
    full_name: str

class Token(BaseModel):
    access_token: str
    token_type: str

class Item(BaseModel):
    id: int
    name: str
    category: str
    owner: str

# HELPERS
def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_access_token(username: str) -> str:
    payload = {
        "sub": username,
        "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401)
    except JWTError:
        raise HTTPException(status_code=401)

    user = users_db.get(username)
    if not user:
        raise HTTPException(status_code=401)

    return user

def admin_only(user: dict):
    if user["role"] != "Admin":
        raise HTTPException(status_code=403, detail="Admin access required")

# AUTH
@app.post("/auth/signup", status_code=201)
async def signup(user: UserCreate):
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="User already exists")

    users_db[user.username] = {
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "hashed_password": get_password_hash(user.password),
        "role": "User"
    }
    return {"msg": "Account created"}

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    token = create_access_token(user["username"])
    return {"access_token": token, "token_type": "bearer"}

# USER PROFILE
@app.get("/users/me", response_model=User)
async def get_profile(current_user: dict = Depends(get_current_user)):
    return current_user

@app.put("/users/me")
async def update_profile(email: EmailStr, full_name: str, current_user: dict = Depends(get_current_user)):
    current_user["email"] = email
    current_user["full_name"] = full_name
    return {"msg": "Profile updated"}

@app.patch("/users/me")
async def patch_profile(full_name: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    if full_name:
        current_user["full_name"] = full_name
    return {"msg": "Profile patched"}

@app.delete("/users/me")
async def delete_profile(current_user: dict = Depends(get_current_user)):
    del users_db[current_user["username"]]
    return {"msg": "Account deleted"}

# ITEMS
@app.post("/items", response_model=Item)
async def create_item(name: str, category: str, current_user: dict = Depends(get_current_user)):
    item = {
        "id": len(items_db) + 1,
        "name": name,
        "category": category,
        "owner": current_user["username"]
    }
    items_db.append(item)
    return item

@app.get("/items/search")
async def search_items(q: str = Query(..., min_length=3)):
    return [i for i in items_db if q.lower() in i["name"].lower()]

# FILE UPLOAD
@app.post("/upload/avatar")
async def upload_avatar(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    file_path = f"{UPLOAD_DIR}/{current_user['username']}_{file.filename}"
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    return {"url": file_path}

# ADMIN
@app.get("/admin/status")
async def system_status(current_user: dict = Depends(get_current_user)):
    admin_only(current_user)
    return {
        "total_users": len(users_db),
        "total_items": len(items_db),
        "server_time": datetime.utcnow(),
        "status": "Running"
    }





       
        
