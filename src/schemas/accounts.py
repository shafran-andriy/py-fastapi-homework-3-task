from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class FilmBase(BaseModel):
    title: str
    genre: str
    price: float

class FilmCreate(FilmBase):
    pass

class FilmUpdate(FilmBase):
    pass

class FilmRead(FilmBase):
    id: int

    class Config:
        from_attributes = True

class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    password: str
    role: str = "user"

class UserRead(UserBase):
    id: int
    role: str

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
