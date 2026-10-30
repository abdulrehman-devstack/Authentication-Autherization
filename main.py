from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import os
import bcrypt
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm,HTTPAuthorizationCredentials
from jose import ExpiredSignatureError, JWTError, jwt
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, Integer, String, create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker
from starlette.middleware.base import BaseHTTPMiddleware

load_dotenv()

MY_APP_SECRETE_KEY = os.getenv("secrete_key")  # type: ignore
algorithm = 'HS256'
Refresh_token_key = os.getenv("refresh_key")  # type: ignore

if not MY_APP_SECRETE_KEY:
    raise ValueError("Error: Also define secrete_key in env file")

if not Refresh_token_key:
    raise ValueError("Error: Also define refresh_key in env file")

assert MY_APP_SECRETE_KEY is not None
assert algorithm is not None

app = FastAPI(title="User Authentication API")
auth = OAuth2PasswordBearer(tokenUrl="login")

Database = os.getenv("database") #type : ignore

if not Database:
    raise ValueError("Error: .env file mein database lazmi define karein!")

abdul = create_engine(Database, pool_recycle=3600, pool_pre_ping=True, echo=True) #type : ignore
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
        
def hash_password(password: str):
    salt = bcrypt.gensalt()
    hash_p = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hash_p.decode('utf-8')

def create_user_table():
    base.metadata.create_all(bind=abdul)

class JWTMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        paths = [ "/", "/login", "/Register", "/docs", "/verifying_token", "/openapi.json", "/redoc", "/logout", "/refresh_token", "/reset-forgot-password", "/forgot-password" ]

        
        if request.url.path in paths or request.url.path.startswith("/static"):
            return await call_next(request)
        
        header = request.headers.get("Authorization")
        if not header or not header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing or invalid Authorization header"}
            )
        
        token = header.split(" ")[1]  
        
        try:
            payload = jwt.decode(token, MY_APP_SECRETE_KEY, algorithms=[algorithm]) # type: ignore
            request.state.user = payload
            
        except JWTError:
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid or expired token"}
            )
            
        response = await call_next(request)
        return response
            
add_middleware()

def create_user_tocken(data: dict):
    encode = data.copy()    
    expire = datetime.utcnow() + timedelta(minutes=10)
    encode.update({"exp": expire})
    encoded_jwt = jwt.encode(encode, MY_APP_SECRETE_KEY, algorithm=algorithm) # type: ignore
    return encoded_jwt

def create_refresh_token(data: dict):
    to_encode = data.copy()
    expires = datetime.utcnow() + timedelta(minutes=20)
    to_encode.update({"exp": expires, "type": "refresh"})
    return jwt.encode(to_encode, Refresh_token_key, algorithm=algorithm) # type: ignore


def create_reset_token(email: str):
    expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode = {"sub": email, "type": "reset_password", "exp": expire}
    return jwt.encode(to_encode, MY_APP_SECRETE_KEY, algorithm=algorithm)#type:ignore

def send_reset_email(email: str, token: str):
    sender = "noreply@authapi.com"
    receiver = email
    reset_link = f"http://127.0.0.1:8001/reset-password?token={token}"

    message = MIMEMultipart("alternative")
    message["Subject"] = "Password Reset Request"
    message["From"] = sender
    message["To"] = receiver

    html = f"""\
    <html>
      <body>
        <h3>Password Reset Request</h3>
        <p>Aapne password reset karne ki request ki hai.</p>
        <p>Apna naya password set karne ke liye niche diye gaye link par click karein:</p>
        <a href="{reset_link}" target="_blank">Reset Password</a>
        <p>Yeh link sirf 15 minutes ke liye valid hai.</p>
      </body>
    </html>
    """
    message.attach(MIMEText(html, "html"))

    try:
        server = smtplib.SMTP(os.getenv("MAIL_SERVER"), int(os.getenv("MAIL_PORT", 2525))) # type: ignore
        server.starttls()
        server.login(os.getenv("MAIL_USERNAME"), os.getenv("MAIL_PASSWORD")) # type: ignore
        server.sendmail(sender, receiver, message.as_string())
        server.quit()
    except Exception as e:
        print(f"Email error: {e}")
        raise HTTPException(status_code=500, detail="Failed to send reset email")

def get_current_verified_token(token: str = Depends(auth), db: Session = Depends(database_get)):
    # Pehle check karein ke token blacklist to nahi hai
    blacklisted = db.query(blacklist).filter(blacklist.token == token).first()
    if blacklisted:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked. Please login again."
        )
    return token
        
class user(base):
    __tablename__ = "Authentication"
    id = Column(Integer, primary_key=True)
    username = Column(String(50), nullable=False)
    email = Column(String(50), unique=True, nullable=False)
    Password = Column(String(255), nullable=False)
    role = Column(String(50), default="user", nullable=False)
    
class blacklist(base):
    __tablename__ = "Blacklist"
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), nullable=False)
    token = Column(String(500), unique=True, nullable=False, index=True)
    expiry_time = Column(DateTime, nullable=False)
    
class user_data(BaseModel):
    username: str
    email: str
    Password: str
    role: str
    
class login_schemas(BaseModel):
    email: str
    Password: str
    
class refresh_token_(BaseModel):
    refresh_token: str
    
class ForgotPasswordSchema(BaseModel):
    email: str

class ResetPasswordSchema(BaseModel):
    token: str
    new_password: str

class ChangePasswordSchema(BaseModel):
    old_password: str
    new_password: str

create_user_table()

@app.get("/")
def Home():
    return {"message": "api is running"}

@app.post("/Register")
def regiter_user(users: user_data, data: Session = Depends(database_get)):
    exist = data.query(user).filter(user.username == users.username).first()
    if exist:
        raise HTTPException(status_code=400, detail="user already exists")
        
    admin_email = "abdulrehman.devstack@gmail.com"
    if users.role == "admin" and users.email != admin_email:
        raise HTTPException(
            status_code=401,
            detail="you are not admin type user"
        )
        
    if users.role != "admin" and users.email == admin_email:
        raise HTTPException(
            status_code=401,
            detail="you are admin not a user"
        )
        
    if "@" not in users.email or "." not in users.email:
        raise HTTPException(status_code=400, detail="Invalid email format")
        
    hashed_bytes = bcrypt.hashpw(users.Password.encode("utf-8"), bcrypt.gensalt())
    hashed_password = hashed_bytes.decode("utf-8")
    
    new_user = user(username=users.username, email=users.email, Password=hashed_password, role=users.role)
    data.add(new_user)
    data.commit()
    data.refresh(new_user)
    return {
        "message": "user created successfully",
        "user": {
            "name": users.username,
            "email": users.email,  
            "role": users.role
        }
    }

@app.post("/login")
def Login_form(form_data: OAuth2PasswordRequestForm = Depends(), data: Session = Depends(database_get)):
    username_or_email = form_data.username.strip()
    data_ = data.query(user).filter((user.email == form_data.username) | (user.username == form_data.username)).first()

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
            "sub": data_.username,
            "role": data_.role
        }
    )
    return {"access_token": tocken, "refresh_token": refreshtoken, "token_type": "bearer"}

@app.get("/verifying_token")
def auth_btn(token: str = Depends(auth)):
    try: 
        payload = jwt.decode(token, MY_APP_SECRETE_KEY, algorithms=[algorithm]) # type: ignore
        username: str | None = payload.get("sub")
        role: str | None = payload.get("role")
        if not username:
            raise HTTPException(status_code=400, detail="username not found")
    
        return {
            "message": f"welcome {username}",
            "role": f"{role}",
        }
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="token expire or invalid login again"
        )
        
@app.post("/refresh_token")
def refresh(data: refresh_token_):
    token = data.refresh_token
    try:
        payload = jwt.decode(token, Refresh_token_key, algorithms=[algorithm]) # type: ignore
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
def dashboard(token: str = Depends(get_current_verified_token)):
    try:
        payload = jwt.decode(token, MY_APP_SECRETE_KEY, algorithms=[algorithm]) # type: ignore
        username = payload.get("sub")
        role = payload.get("role")
        
        return {
            "status": "success",
            "message": f"Welcome to the secret dashboard, {username}!",
            "role": role,
            "data": "Only authorized user can see this via Verified Token Dependency"
        }
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
        
@app.get("/admin/dashboard")
def admin_dashboard(token: str = Depends(get_current_verified_token)):
    try:
        payload = jwt.decode(token, MY_APP_SECRETE_KEY, algorithms=[algorithm]) # type: ignore
        role = payload.get("role")
        
        if role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, 
                detail="You are not authorized! Admin access required."
            )
            
        return {"message": "Welcome to Admin Panel!"}
        
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    
@app.post("/logout")
def logout(
    token: str = Depends(get_current_verified_token), 
    data: Session = Depends(database_get)
):
    try:
        payload = jwt.decode(token, MY_APP_SECRETE_KEY, algorithms=[algorithm]) # type: ignore
        username: str | None = payload.get("sub")
        exp_time = payload.get("exp")
        
        if not username or not exp_time:
            raise HTTPException(status_code=401, detail="Invalid token data")
            
        expiry_time = datetime.utcfromtimestamp(exp_time)
        
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    data_base = blacklist(
        username=username,
        token=token,
        expiry_time=expiry_time
    )
    data.add(data_base)
    data.commit()
    
    return {
        "message": "User logged out successfully"
    }


@app.post("/forgot-password")
def forgot_password(body: ForgotPasswordSchema, data: Session = Depends(database_get)):
    user_record = data.query(user).filter(user.email == body.email).first()
    if not user_record:
        raise HTTPException(status_code=404, detail="Email not found")
    
    token = create_reset_token(body.email)
    
    send_reset_email(body.email, token)
    
    return {"message": "Password reset link sent to your email"}

@app.post("/reset-forgot-password")
def reset_password(body: ResetPasswordSchema, data: Session = Depends(database_get)):
    try:
        # 🛠️ URL handle karne ka logic: Agar poora link bhej diya ho to sirf token nikaley
        actual_token = body.token
        if "?token=" in actual_token:
            actual_token = actual_token.split("?token=")[1]

        # Ab actual_token decode hoga, poora URL nahi
        payload = jwt.decode(actual_token, MY_APP_SECRETE_KEY, algorithms=[algorithm]) # type: ignore
        
        if payload.get("type") != "reset_password":
            raise HTTPException(status_code=401, detail="Invalid token type")
        
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        
        user_record = data.query(user).filter(user.email == email).first()
        if not user_record:
            raise HTTPException(status_code=404, detail="User not found")
        
        hashed_bytes = bcrypt.hashpw(body.new_password.encode("utf-8"), bcrypt.gensalt())
        setattr(user_record, "Password", hashed_bytes.decode("utf-8"))
        data.commit()
        
        return {"message": "Password reset successfully. You can login now."}
        
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Reset token expired. Please request a new one.")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    
# @app.post("/reset-password")
# def reset():
#     pass

@app.post("/reset-password")
def change_user_password(
    body: ChangePasswordSchema, 
    token: str = Depends(get_current_verified_token), 
    data: Session = Depends(database_get)
):
    try:
        payload = jwt.decode(token, MY_APP_SECRETE_KEY, algorithms=[algorithm]) # type: ignore
        username = payload.get("sub")
        
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token payload")
            
        user_record = data.query(user).filter(user.username == username).first()
        if not user_record:
            raise HTTPException(status_code=404, detail="User not found")
            
        validate_old_password = bcrypt.checkpw(
            body.old_password.encode("utf-8"), 
            user_record.Password.encode("utf-8")
        )
        if not validate_old_password:
            raise HTTPException(status_code=400, detail=" (Incorrect old password)")
            
        hashed_bytes = bcrypt.hashpw(body.new_password.encode("utf-8"), bcrypt.gensalt())
        user_record.Password = hashed_bytes.decode("utf-8") # type:ignore
        
        data.commit()
        return {"message": "password updated success fully"}
        
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="token expired login again")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


   
        
    # blacklist.add(id,username,token)
    
    # return {"message": "Successfully logged out. Token has been revoked."}
        
        
        
        
    # return {
    #     "message" : "you are authorized!",
    #     "Token": token
    # }
    
    
