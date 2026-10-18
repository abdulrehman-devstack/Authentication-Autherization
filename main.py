import uvicorn
from fastapi import FastAPI,Depends,HTTPException,status,Header
from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy import create_engine,Integer,String,Column
from sqlalchemy.orm import sessionmaker,declarative_base,Session
import bcrypt
import email_validator
from jose import jwt,JWTError,ExpiredSignatureError
from datetime import datetime, timedelta


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

def email_validation():
    # jwt.encode(My_app_Secrete_key,
    pass
    

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
    
        
        
        
    # return {
    #     "message" : "you are authorized!",
    #     "Token": token
    # }
    
    
