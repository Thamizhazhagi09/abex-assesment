# abex-assesment
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "sqlite:///./myokr.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()



from sqlalchemy import Column, Integer, String, ForeignKey, Boolean, Float
from sqlalchemy.orm import relationship
from database import Base

class Organisation(Base):
    _tablename_ = "organisations"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True)
    departments = relationship("Department", back_populates="organisation")

class Department(Base):
    _tablename_ = "departments"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    organisation_id = Column(Integer, ForeignKey("organisations.id"))
    organisation = relationship("Organisation", back_populates="departments")
    teams = relationship("Team", back_populates="department")

class Team(Base):
    _tablename_ = "teams"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    department_id = Column(Integer, ForeignKey("departments.id"))
    department = relationship("Department", back_populates="teams")
    users = relationship("User", back_populates="team")
    okrs = relationship("OKR", back_populates="team")

class User(Base):
    _tablename_ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True)
    hashed_password = Column(String)
    team_id = Column(Integer, ForeignKey("teams.id"))
    team = relationship("Team", back_populates="users")

class OKR(Base):
    _tablename_ = "okrs"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    description = Column(String)
    progress = Column(Float, default=0.0)
    team_id = Column(Integer, ForeignKey("teams.id"))
    team = relationship("Team", back_populates="okrs")
    owner_id = Column(Integer, ForeignKey("users.id"))

    from pydantic import BaseModel
from typing import Optional

class OKRBase(BaseModel):
    title: str
    description: Optional[str] = None

class OKRCreate(OKRBase):
    team_id: int
    owner_id: int

class OKROut(OKRBase):
    id: int
    progress: float
    class Config:
        orm_mode = True

class UserCreate(BaseModel):
    username: str
    password: str

    from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta

SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict):
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    data.update({"exp": expire})
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

from fastapi import FastAPI
from database import Base, engine
from routers import users, okrs, auth, orgs

Base.metadata.create_all(bind=engine)

app = FastAPI(title="MyOKR")

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(orgs.router)
app.include_router(okrs.router)

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import SessionLocal
from models import OKR
from schemas import OKRCreate, OKROut

router = APIRouter(prefix="/okrs", tags=["OKRs"])

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/", response_model=OKROut)
def create_okr(okr: OKRCreate, db: Session = Depends(get_db)):
    db_okr = OKR(**okr.dict())
    db.add(db_okr)
    db.commit()
    db.refresh(db_okr)
    return db_okr

@router.get("/{okr_id}", response_model=OKROut)
def read_okr(okr_id: int, db: Session = Depends(get_db)):
    okr = db.query(OKR).filter(OKR.id == okr_id).first()
    if not okr:
        raise HTTPException(status_code=404, detail="OKR not found")
    return okr

