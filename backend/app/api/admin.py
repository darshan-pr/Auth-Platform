from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_
from app.db import get_db
from app.models.app import App
from app.models.user import User
from pydantic import BaseModel, EmailStr
from typing import Optional, List
import secrets
from datetime import datetime

router = APIRouter(prefix="/admin")

# ============== Pydantic Schemas ==============

class AppCreateRequest(BaseModel):
    name: str
    description: Optional[str] = None
    otp_enabled: bool = True
    login_notification_enabled: bool = False
    passkey_enabled: bool = False
    access_token_expiry_minutes: int = 30
    refresh_token_expiry_days: int = 7
    redirect_uris: Optional[str] = None  # Comma-separated allowed redirect URIs

class AppUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    otp_enabled: Optional[bool] = None
    login_notification_enabled: Optional[bool] = None
    passkey_enabled: Optional[bool] = None
    access_token_expiry_minutes: Optional[int] = None
    refresh_token_expiry_days: Optional[int] = None
    redirect_uris: Optional[str] = None

class AppResponse(BaseModel):
    id: int
    app_id: str
    name: Optional[str]
    description: Optional[str]
    created_at: Optional[datetime]
    
    class Config:
        from_attributes = True

class AppCredentialsResponse(BaseModel):
    app_id: str
    app_secret: str

class UserCreateRequest(BaseModel):
    email: EmailStr
    app_id: Optional[str] = None

class UserUpdateRequest(BaseModel):
    is_active: Optional[bool] = None
    app_id: Optional[str] = None

class UserResponse(BaseModel):
    id: int
    email: str
    app_id: Optional[str]
    is_active: bool
    created_at: Optional[datetime]
    
    class Config:
        from_attributes = True

# ============== App Management ==============

@router.post("/apps", response_model=dict)
def create_app(request: AppCreateRequest, db: Session = Depends(get_db)):
    """Create a new application with unique app_id and app_secret"""
    try:
        app_id = secrets.token_hex(8)
        app_secret = secrets.token_hex(16)

        app = App(
            app_id=app_id, 
            app_secret=app_secret,
            name=request.name,
            description=request.description,
            otp_enabled=request.otp_enabled,
            login_notification_enabled=request.login_notification_enabled,
            passkey_enabled=request.passkey_enabled,
            access_token_expiry_minutes=request.access_token_expiry_minutes,
            refresh_token_expiry_days=request.refresh_token_expiry_days,
            redirect_uris=request.redirect_uris
        )
        db.add(app)
        db.commit()
        db.refresh(app)

        return {
            "id": app.id,
            "app_id": app_id, 
            "app_secret": app_secret,
            "name": app.name,
            "otp_enabled": app.otp_enabled,
            "login_notification_enabled": app.login_notification_enabled,
            "passkey_enabled": app.passkey_enabled,
            "access_token_expiry_minutes": app.access_token_expiry_minutes,
            "refresh_token_expiry_days": app.refresh_token_expiry_days,
            "redirect_uris": app.redirect_uris,
            "message": "App created successfully"
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create app: {str(e)}"
        )

# Keep old endpoint for backward compatibility
@router.post("/create-app", response_model=dict, include_in_schema=False)
def create_app_legacy(request: AppCreateRequest = None, db: Session = Depends(get_db)):
    if request is None:
        request = AppCreateRequest(name="Unnamed App")
    return create_app(request, db)

@router.get("/apps", response_model=List[dict])
def list_apps(
    search: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """List all registered applications"""
    query = db.query(App)
    
    if search:
        query = query.filter(
            or_(
                App.name.ilike(f"%{search}%"),
                App.app_id.ilike(f"%{search}%")
            )
        )
    
    apps = query.order_by(App.created_at.desc()).all()
    return [{
        "id": app.id,
        "app_id": app.app_id,
        "name": app.name,
        "description": app.description,
        "is_active": True,  # All apps are active by default
        "otp_enabled": app.otp_enabled,
        "login_notification_enabled": app.login_notification_enabled,
        "passkey_enabled": app.passkey_enabled,
        "access_token_expiry_minutes": app.access_token_expiry_minutes,
        "refresh_token_expiry_days": app.refresh_token_expiry_days,
        "redirect_uris": app.redirect_uris,
        "created_at": app.created_at.isoformat() if app.created_at else None
    } for app in apps]

@router.get("/apps/{app_id}", response_model=dict)
def get_app(app_id: str, db: Session = Depends(get_db)):
    """Get a specific application by app_id"""
    app = db.query(App).filter(App.app_id == app_id).first()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")
    
    return {
        "id": app.id,
        "app_id": app.app_id,
        "name": app.name,
        "description": app.description,
        "otp_enabled": app.otp_enabled,
        "login_notification_enabled": app.login_notification_enabled,
        "passkey_enabled": app.passkey_enabled,
        "access_token_expiry_minutes": app.access_token_expiry_minutes,
        "refresh_token_expiry_days": app.refresh_token_expiry_days,
        "redirect_uris": app.redirect_uris,
        "created_at": app.created_at.isoformat() if app.created_at else None,
        "updated_at": app.updated_at.isoformat() if app.updated_at else None
    }

@router.put("/apps/{app_id}", response_model=dict)
def update_app(app_id: str, request: AppUpdateRequest, db: Session = Depends(get_db)):
    """Update an application's properties"""
    app = db.query(App).filter(App.app_id == app_id).first()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")
    
    if request.name is not None:
        app.name = request.name
    if request.description is not None:
        app.description = request.description
    if request.otp_enabled is not None:
        app.otp_enabled = request.otp_enabled
    if request.login_notification_enabled is not None:
        app.login_notification_enabled = request.login_notification_enabled
    if request.passkey_enabled is not None:
        app.passkey_enabled = request.passkey_enabled
    if request.access_token_expiry_minutes is not None:
        app.access_token_expiry_minutes = request.access_token_expiry_minutes
    if request.refresh_token_expiry_days is not None:
        app.refresh_token_expiry_days = request.refresh_token_expiry_days
    if request.redirect_uris is not None:
        app.redirect_uris = request.redirect_uris
    
    db.commit()
    db.refresh(app)
    
    return {
        "id": app.id,
        "app_id": app.app_id,
        "name": app.name,
        "description": app.description,
        "otp_enabled": app.otp_enabled,
        "login_notification_enabled": app.login_notification_enabled,
        "passkey_enabled": app.passkey_enabled,
        "access_token_expiry_minutes": app.access_token_expiry_minutes,
        "refresh_token_expiry_days": app.refresh_token_expiry_days,
        "redirect_uris": app.redirect_uris,
        "message": "App updated successfully"
    }

@router.delete("/apps/{app_id}")
def delete_app(app_id: str, db: Session = Depends(get_db)):
    """Delete an application and all its associated users"""
    app = db.query(App).filter(App.app_id == app_id).first()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")
    
    # Delete all users associated with this app
    db.query(User).filter(User.app_id == app_id).delete()
    db.delete(app)
    db.commit()
    
    return {"message": "App and its users deleted successfully"}

@router.get("/apps/{app_id}/credentials", response_model=AppCredentialsResponse)
def get_app_credentials(app_id: str, db: Session = Depends(get_db)):
    """Get the credentials for an application"""
    app = db.query(App).filter(App.app_id == app_id).first()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")
    
    return AppCredentialsResponse(app_id=app.app_id, app_secret=app.app_secret)

@router.post("/apps/{app_id}/regenerate-secret", response_model=AppCredentialsResponse)
def regenerate_app_secret(app_id: str, db: Session = Depends(get_db)):
    """Regenerate the secret for an application"""
    app = db.query(App).filter(App.app_id == app_id).first()
    if not app:
        raise HTTPException(status_code=404, detail="App not found")
    
    app.app_secret = secrets.token_hex(16)
    db.commit()
    db.refresh(app)
    
    return AppCredentialsResponse(app_id=app.app_id, app_secret=app.app_secret)

# ============== User Management ==============

@router.get("/users", response_model=dict)
def list_users(
    search: Optional[str] = None,
    app_id: Optional[str] = None,
    is_active: Optional[bool] = None,
    limit: int = Query(default=50, le=100),
    offset: int = 0,
    db: Session = Depends(get_db)
):
    """List all users with optional filters"""
    query = db.query(User)
    
    if search:
        query = query.filter(User.email.ilike(f"%{search}%"))
    if app_id:
        query = query.filter(User.app_id == app_id)
    if is_active is not None:
        query = query.filter(User.is_active == is_active)
    
    total = query.count()
    users = query.order_by(User.created_at.desc()).offset(offset).limit(limit).all()
    
    return {
        "total": total,
        "users": [{
            "id": user.id,
            "email": user.email,
            "app_id": user.app_id,
            "is_active": user.is_active,
            "created_at": user.created_at.isoformat() if user.created_at else None
        } for user in users]
    }

@router.post("/users", response_model=dict)
def create_user(request: UserCreateRequest, db: Session = Depends(get_db)):
    """Create a new user"""
    if not request.app_id:
        raise HTTPException(status_code=400, detail="app_id is required")
    
    # Check if user already exists for this app
    existing = db.query(User).filter(
        User.email == request.email,
        User.app_id == request.app_id
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="User with this email already exists for this app")
    
    user = User(
        email=request.email,
        app_id=request.app_id,
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    return {
        "id": user.id,
        "email": user.email,
        "app_id": user.app_id,
        "is_active": user.is_active,
        "message": "User created successfully"
    }

@router.get("/users/{user_id}", response_model=dict)
def get_user(user_id: int, db: Session = Depends(get_db)):
    """Get a specific user by ID"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "id": user.id,
        "email": user.email,
        "app_id": user.app_id,
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "updated_at": user.updated_at.isoformat() if user.updated_at else None
    }

@router.put("/users/{user_id}", response_model=dict)
def update_user(user_id: int, request: UserUpdateRequest, db: Session = Depends(get_db)):
    """Update a user's properties"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if request.is_active is not None:
        user.is_active = request.is_active
    if request.app_id is not None:
        user.app_id = request.app_id
    
    db.commit()
    db.refresh(user)
    
    return {
        "id": user.id,
        "email": user.email,
        "app_id": user.app_id,
        "is_active": user.is_active,
        "message": "User updated successfully"
    }

@router.delete("/users/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db)):
    """Delete a user"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    db.delete(user)
    db.commit()
    
    return {"message": "User deleted successfully"}

# ============== Dashboard Stats ==============

@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    """Get dashboard statistics"""
    total_apps = db.query(App).count()
    total_users = db.query(User).count()
    active_users = db.query(User).filter(User.is_active == True).count()
    
    return {
        "total_apps": total_apps,
        "total_users": total_users,
        "active_users": active_users,
        "inactive_users": total_users - active_users
    }
