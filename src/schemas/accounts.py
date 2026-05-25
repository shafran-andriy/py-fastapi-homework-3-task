from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class EmailBaseSchema(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: EmailStr) -> str:
        return accounts_validators.validate_email(str(value).lower())


class PasswordBaseSchema(BaseModel):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserRegistrationRequestSchema(EmailBaseSchema,
                                    PasswordBaseSchema):
    pass


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    model_config = {
        "from_attributes": True
    }


class UserActivationRequestSchema(EmailBaseSchema):
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(EmailBaseSchema):
    pass


class PasswordResetCompleteRequestSchema(EmailBaseSchema, PasswordBaseSchema):
    token: str


class UserLoginRequestSchema(EmailBaseSchema):
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
