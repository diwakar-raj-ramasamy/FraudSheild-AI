from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.security import (
    verify_password,
    get_password_hash,
    create_access_token,
    get_current_user_payload,
    validate_password_strength,
    require_admin
)
from app.core.rate_limiter import auth_rate_limiter
from app.models import User
from app.schemas import Token, LoginRequest, UserCreate, UserOut

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/login", response_model=Token, dependencies=[Depends(auth_rate_limiter)])
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email.strip().lower()).first()
    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Account is disabled")

    access_token = create_access_token(subject=user.email, role=user.role)
    return Token(
        access_token=access_token,
        token_type="bearer",
        role=user.role,
        user_email=user.email
    )

@router.post("/register", response_model=UserOut)
def register(
    user_in: UserCreate,
    admin: dict = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Registers a new security analyst or admin account.
    Restricted to authenticated administrators and enforces strict password complexity.
    """
    email_clean = user_in.email.strip().lower()
    existing = db.query(User).filter(User.email == email_clean).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    is_valid, reason = validate_password_strength(user_in.password)
    if not is_valid:
        raise HTTPException(status_code=400, detail=reason)

    user = User(
        email=email_clean,
        hashed_password=get_password_hash(user_in.password),
        full_name=user_in.full_name,
        role=user_in.role or "analyst"
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@router.get("/me", response_model=dict)
def get_me(payload: dict = Depends(get_current_user_payload), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.get("sub")).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "is_active": user.is_active
    }
