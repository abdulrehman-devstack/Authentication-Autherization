from sqlalchemy import engine,Column,Integer,String,create_engine
from sqlalchemy.orm import sessionmaker,declarative_base

Database = "mysql+pymysql://root:ar4729189@localhost:3306/aws"

abdul = create_engine(Database , echo = True)
session =sessionmaker(bind=abdul)
base = declarative_base()


class user(base):
    __tablename__ = "users"
    id = Column(Integer,primary_key=True)
    name = Column(String(50))
    marks = Column(Integer)
    
base.metadata.create_all(bind=abdul)

data =session()

new_student = [user(name="abdulrehman",marks = 1087),user(name = "Wasif",marks = 1093),user(name = "Ali",marks = 1050),user(name = "Haris",marks = 1000),user(name = "Ahsan",marks = 1020)]

data.add_all(new_student)
data.commit()
deleting = data.query(user).filter(user.marks == 1090).delete()

if deleting:
    data.commit()
    print("deleted")
else:
    print("not found")
    
student = data.query(user).all()
for i in student:
    print(i.id,i.name,i.marks)


data.close()

# 573247714279



    
