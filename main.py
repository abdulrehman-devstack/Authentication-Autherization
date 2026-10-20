import uvicorn
from fastapi import FastAPI,Depends,HTTPException,status,Header,Response,Request
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy import create_engine,Integer,String,Column
from sqlalchemy.orm import sessionmaker,declarative_base,Session
import bcrypt
import email_validator
from jose import jwt,JWTError,ExpiredSignatureError
from datetime import datetime, timedelta
from starlette.middleware.base import BaseHTTPMiddleware


My_app_Secrete_key = "manualchoice"
algorithm = 'HS256'
Refresh_token_key = 'refreshtoken'

app = FastAPI(title="User Authentication API")

auth = OAuth2PasswordBearer(tokenUrl="login")

Database = "mysql+pymysql://root:ar4729189@localhost:3306/aws"
abdul = create_engine(Database,pool_recycle=3600, pool_pre_ping= True , echo=True)
session = sessionmaker(bind=abdul)
base = declarative_base()
data = session()

def add_middleware():
    app.add_middleware(JWTMiddleware)


def database_get():
    data = session()
    try:
        yield data
    finally:
        data.close()
        
def hash_password(password : str):
    salt = bcrypt.gensalt()
    hash_p = bcrypt.hashpw(password.encode('utf-8'), salt)
    # bcrypt.checkpw(password.encode('utf-8'),hash_p)
    return hash_p.decode('utf-8')


def create_user_table():
    base.metadata.create_all(bind=abdul)

class JWTMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Yahan sirf woh paths hon jo sach mein PUBLIC hain (Dashboard yahan nahi hona chahiye!)
        paths = [
            "/", 
            "/login", 
            "/Register", 
            "/docs", 
            "/verifying_token", 
            "/openapi.json", 
            "/redoc", 
            "/refresh_token"
        ]
        
        if request.url.path in paths or request.url.path.startswith("/static"):
            return await call_next(request)
        
        header = request.headers.get("Authorization")
        if not header or not header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing or invalid Authorization header"}
            )
        
        # ⚠️ YAHAN GHATI THEEK KI HAI: Bearer ke baad ka poora token uthana hai (.split()[1])
        token = header.split(" ")[1]  
        
        try:
            payload = jwt.decode(token, My_app_Secrete_key, algorithms=[algorithm]) 
            request.state.user = payload
            
        except JWTError:
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid or expired token"}
            )
            
        response = await call_next(request)
        return response
            
add_middleware()

def create_user_tocken(data:dict):
    encode = data.copy()    
    expire = datetime.utcnow() + timedelta(seconds=30)
    encode.update({"exp":expire})
    encoded_jwt = jwt.encode(encode,My_app_Secrete_key,algorithm=algorithm)
    return encoded_jwt

def create_refresh_token(data : dict):
    to_encode = data.copy()
    expires = datetime.utcnow()+timedelta(minutes=2)
    to_encode.update({"exp":expires,"type":"refresh"})
    # encoded_jwt = jwt.encode(To_encode,Refresh_token_key,algorithm=algorithm)  
    return jwt.encode(to_encode,Refresh_token_key,algorithm=algorithm) 
    
class user(base):
    __tablename__ = "Authentication"
    id = Column(Integer ,primary_key = True)
    username = Column(String(50),unique=True,nullable=False)
    email = Column(String(50),unique=True,nullable=False)
    Password = Column(String(255),nullable=False)
    role = Column(String(50), default = "user",nullable=False)
    
class user_data(BaseModel):
    username : str
    email : str
    Password : str
    role : str
    
class login_schemas(BaseModel):
    email : str
    Password : str
    
class refresh_token_(BaseModel):
    refresh_token : str

create_user_table()

@app.get("/")
def Home():
    return{"message" : "api is running"}

@app.post("/Register")
def regiter_user(users:user_data, data : Session = Depends(database_get)):
    exist = data.query(user).filter(user.username == users.username).first()
    if exist:
        raise HTTPException(status_code=400, detail="user already exists")
        # return{
        #     "message":" user already exists"
        # }
    if "@" not in users.email or "." not in users.email:
        raise HTTPException(status_code=400, detail="Invalid email format")
    hashed_bytes = bcrypt.hashpw(users.Password.encode("utf-8"),bcrypt.gensalt())
    hashed_password = hashed_bytes.decode("utf-8")
    
    # hashed_Password = hash_password(users.Password)
    new_user = user(username = users.username,email = users.email, Password = hashed_password,role = users.role)
    data.add(new_user)
    data.commit()
    data.refresh(new_user)
    return {
        "message" : "user created successfully",
        "user" : {
            "name" : users.username,
            "email": users.email,  
            "role" : users.role
        }
    }

@app.post("/login")
def Login_form(form_data: OAuth2PasswordRequestForm = Depends(),data: Session = Depends(database_get)):
  data_ = data.query(user).filter(user.email == form_data.username).first()

  if not data_:
    raise HTTPException(status_code=400, detail="invalid email or password")

  validate_Password = bcrypt.checkpw(
      form_data.password.encode("utf-8"), data_.Password.encode("utf-8")
  )

  if not validate_Password:
    raise HTTPException(status_code=400, detail="invalid email or password")

  tocken = create_user_tocken(
      data={
          "sub": data_.username,
          "role": data_.role,
      }
  )
  refreshtoken = create_refresh_token(
      data={
          "sub":data_.username,
          "role":data_.role
      }
  )
  return {"access_token": tocken,"refresh_token":refreshtoken, "token_type": "bearer"}

    
@app.get("/verifying_token")
def auth_btn(token : str = Depends(auth)):
    try: 
        payload = jwt.decode(token,My_app_Secrete_key,algorithms=[algorithm])
        username: str | None = payload.get("sub")
        role : str | None = payload.get("role")
        if not username:
            raise HTTPException(status_code=400,detail="username not found")
    
        return{
            "message":f"welcome {username}",
            "role": f"{role}",
    }
    except JWTError:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = "token expire or invalid login again"
        )
        
@app.post("/refresh_token")
def refresh(data: refresh_token_):
    token = data.refresh_token
    try:
        payload = jwt.decode(token, Refresh_token_key, algorithms=[algorithm])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="invalid token type")
        
        username = payload.get("sub")
        user_role = payload.get("role")
        
        if not username:
            raise HTTPException(status_code=401, detail="invalid payload")
        
        new_access_token = create_user_tocken({"sub": username, "role": user_role})
        
        return {"access_token": new_access_token, "token_type": "bearer"}
        
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="refresh token expired. Please login again")
    except JWTError:
        raise HTTPException(status_code=401, detail="invalid refresh token")
    
    
    
@app.get("/dashboard")
def dashboard(request:Request):
    current_user = getattr(request.state,"user",None)
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication state missing"
        )
    
    return {
        "status": "success",
        "message": f"Welcome to the secret dashboard, {current_user.get('sub')}!",
        "role": current_user.get('role'),
        "data": "Only authorized user can see this via JWT Middleware"
    }
    
    
    
# @app.get("/dashboard")
# def protected_dashboard(token: str = Depends(auth)):
#     try:
#         payload = jwt.decode(token, My_app_Secrete_key, algorithms=[algorithm])
#         username = payload.get("sub")
#         role = payload.get("role")
        
#         return {
#             "status": "success",
#             "message": f"Welcome to the secret dashboard, {username}!",
#             "your_role": role,
#             "data": "Only authorized user can see"
#         }
#     except JWTError:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Invalid or expired token. Please login again."
#         )
        
        
@app.get("/admin/dashboard")
def admin_dashboard(token: str = Depends(auth)):
    try:
        payload = jwt.decode(token, My_app_Secrete_key, algorithms=[algorithm])
        role = payload.get("role")
        
        if role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, 
                detail="You are not authorized! Admin access required."
            )
            
        return {"message": "Welcome to Admin Panel!"}
        
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
        
        
        
    # return {
    #     "message" : "you are authorized!",
    #     "Token": token
    # }
    
    
