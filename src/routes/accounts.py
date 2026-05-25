from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import delete, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from config import BaseAppSettings, get_jwt_auth_manager, get_settings
from database import (
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
    UserGroupEnum,
    UserGroupModel,
    UserModel,
    get_db,
)
from exceptions import BaseSecurityError
from schemas import (
    MessageResponseSchema,
    PasswordResetCompleteRequestSchema,
    PasswordResetRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
    UserActivationRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


def _as_aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


async def _get_user_by_email(db: AsyncSession, email: str) -> UserModel | None:
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    return result.scalars().first()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> UserModel:
    existing_user = await _get_user_by_email(db, user_data.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    result = await db.execute(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    user_group = result.scalars().first()
    if user_group is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    user = UserModel.create(
        email=user_data.email,
        raw_password=user_data.password,
        group_id=user_group.id,
    )
    db.add(user)

    try:
        await db.flush()
        db.add(ActivationTokenModel(user_id=user.id))
        await db.commit()
        await db.refresh(user)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    return user


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def activate_user(
    activation_data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    user = await _get_user_by_email(db, activation_data.email)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    result = await db.execute(
        select(ActivationTokenModel).where(
            ActivationTokenModel.user_id == user.id,
            ActivationTokenModel.token == activation_data.token,
        )
    )
    activation_token = result.scalars().first()

    if (
        activation_token is None
        or _as_aware_utc(activation_token.expires_at) <= datetime.now(timezone.utc)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user.is_active = True
    await db.delete(activation_token)
    await db.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def request_password_reset(
    reset_data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    response = MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )

    user = await _get_user_by_email(db, reset_data.email)
    if user is None or not user.is_active:
        return response

    await db.execute(
        delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
    )
    db.add(PasswordResetTokenModel(user_id=user.id))
    await db.commit()

    return response


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def complete_password_reset(
    reset_data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    user = await _get_user_by_email(db, reset_data.email)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    result = await db.execute(
        select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
    )
    reset_token = result.scalars().first()

    if (
        reset_token is None
        or reset_token.token != reset_data.token
        or _as_aware_utc(reset_token.expires_at) <= datetime.now(timezone.utc)
    ):
        if reset_token is not None:
            await db.delete(reset_token)
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    try:
        user.password = reset_data.password
        await db.delete(reset_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )

    return MessageResponseSchema(message="Password reset successfully.")


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def login_user(
    login_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
) -> UserLoginResponseSchema:
    user = await _get_user_by_email(db, login_data.email)
    if user is None or not user.verify_password(login_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    token_data = {"user_id": user.id}
    access_token = jwt_manager.create_access_token(token_data)
    refresh_token = jwt_manager.create_refresh_token(
        token_data,
        expires_delta=timedelta(days=settings.LOGIN_TIME_DAYS),
    )
    refresh_token_record = RefreshTokenModel.create(
        user_id=user.id,
        days_valid=settings.LOGIN_TIME_DAYS,
        token=refresh_token,
    )
    db.add(refresh_token_record)

    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post(
    "/api/v1/accounts/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def refresh_access_token(
    token_data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
) -> TokenRefreshResponseSchema:
    try:
        payload = jwt_manager.decode_refresh_token(token_data.refresh_token)
    except BaseSecurityError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        )

    result = await db.execute(
        select(RefreshTokenModel).where(RefreshTokenModel.token == token_data.refresh_token)
    )
    refresh_token = result.scalars().first()
    if refresh_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    user_id = payload.get("user_id")
    result = await db.execute(select(UserModel).where(UserModel.id == user_id))
    user = result.scalars().first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    return TokenRefreshResponseSchema(
        access_token=jwt_manager.create_access_token({"user_id": user.id})
    )
