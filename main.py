import uvicorn
from fastapi import FastAPI,Depends,HTTPException
from pydantic import BaseModel
from sqlalchemy import create_engine,Integer,String,Column
from sqlalchemy.orm import sessionmaker,declarative_base,Session
import bcrypt


app = FastAPI()

Database = "mysql+pymysql://root:ar4729189@localhost:3306/aws"
abdul = create_engine(Database,echo=True)
session = sessionmaker(bind=abdul)
base = declarative_base()
data = session()

def get_db():
    data = session()
    try:
        yield data
    finally:
        data.close()
        
def hash_password(password : str):
    salt = bcrypt.gensalt()
    hash_p = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hash_p.decode('utf-8')

class user(base):
    __tablename__ = "Authentication"
    id = Column(Integer ,primary_key = True)
    username = Column(String(50),unique=True,nullable=False)
    Password = Column(String(50),nullable=False)
    role = Column(String(50), default = "user",nullable=False)
    
base.metadata.create_all(bind=abdul)

class user_data(BaseModel):
    username : str
    password : str
    email : str
    role : str


@app.get("/")
def Home():
    return{"message" : "api is running"}

@app.post("/register")
def regiter_user(users:user_data, data : Session = Depends(get_db)):
    if data.query(user).filter(user.username == users.username).first():
        # return{
        #     "message":" user already exists"
        # }
        raise HTTPException(status_code=400,detail="user already exists")
    new_user = user(username = users.username,Password = users.password,role = users.role)
    password = hash_password(users.password)
    data.add(new_user)
    data.commit()
    return {
        "message" : "user created successfully",
        "user" : {
            "name" : users.username,
            "role" : users.role
        }
    }
