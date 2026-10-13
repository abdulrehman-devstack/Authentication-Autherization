import uvicorn
from fastapi import FastAPI,Depends,HTTPException
from pydantic import BaseModel
from sqlalchemy import create_engine,Integer,String,Column
from sqlalchemy.orm import sessionmaker,declarative_base,Session
import bcrypt
import email_validator
from jose import jwt
from datetime import datetime, timedelta


My_app_Secrete_key = "la;sdjlsdjlksdjflkdf"
algorithm = 'HS256'

app = FastAPI(title="User Authentication API")

Database = "mysql+pymysql://root:ar4729189@localhost:3306/aws"
abdul = create_engine(Database,echo=True)
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
    bcrypt.checkpw(password.encode('utf-8'),hash_p)
    return hash_p.decode('utf-8')


def create_user_table():
    base.metadata.create_all(bind=abdul)

def email_validation():
    # jwt.encode(My_app_Secrete_key,
    pass
    

def create_user_tocken(data:dict):
    encode = data.copy()    
    expire = datetime.utcnow() + timedelta(minutes=30)
    encode.update({"exp":expire})
    encoded_jwt = jwt.encode(encode,My_app_Secrete_key,algorithm=algorithm)
    return encoded_jwt
    
class user(base):
    __tablename__ = "Authentication"
    id = Column(Integer ,primary_key = True)
    username = Column(String(50),unique=True,nullable=False)
    email = Column(String(50),unique=True,nullable=False)
    Password = Column(String(50),nullable=False)
    role = Column(String(50), default = "user",nullable=False)
    
class user_data(BaseModel):
    username : str
    email : str
    Password : str
    role : str
    
class login_schemas(BaseModel):
    email : str
    Password : str
    

create_user_table()

@app.get("/")
def Home():
    return{"message" : "api is running"}

@app.post("/Register")
def regiter_user(users:user_data, data : Session = Depends(database_get)):
    if data.query(user).filter(user.username == users.username).first():
        # return{
        #     "message":" user already exists"
        # }
        raise HTTPException(status_code=400,detail="user already exists")
    email_validator.validate_email(user_data.email and login_schemas.email)
    Password = hash_password(users.Password)
    new_user = user(username = users.username,email = users.email, Password = users.Password,role = users.role)
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
    
@app.post("/Login")
def Login_form(users:login_schemas, data : Session = Depends(database_get)):
    data_ = data.query(user).filter(user.email == users.email).first()
    if not data_:
        raise HTTPException(status_code=400,detail = "invalid email or password")
    new_user = {
        "user_email": data_.email,
        "user_password": data_.Password
    }
    # data.add(new_user)
    # data.commit()
    email_validator.validate_email(login_schemas.email)
    validate_Password = bcrypt.checkpw(users.Password.encode('utf-8'), data_.Password.encode('utf-8'))
    if not validate_Password:
        raise HTTPException(status_code=400,detail = "invalid email or password")
    tocken = create_user_tocken(data={"sub":data_.username,"role":data_.role,})
    return {
        "access_tocken":tocken,
        "tocken_type":"bearer"
    }
    
