import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel
from sqlalchemy import create_engine,Integer,String,Column
from sqlalchemy.orm import sessionmaker,declarative_base



app = FastAPI()

Database = "mysql+pymysql://root:ar4729189@localhost:3306/aws"
abdul = create_engine(Database,echo=True)
session = sessionmaker(bind=abdul)
base = declarative_base()
data = session()

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
    role : str


@app.get("/")
def Home():
    return{"message" : "api is running"}

