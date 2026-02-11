from sqlalchemy.orm import Session
from ..models import user as user_model

def create_user(db: Session, user_data: dict):
    new_user = user_model.User(**user_data)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

def get_user_by_email(db: Session, email: str, app_id: str = None):
    """Get user by email and app_id (both required for uniqueness)"""
    query = db.query(user_model.User).filter(user_model.User.email == email)
    if app_id:
        query = query.filter(user_model.User.app_id == app_id)
    return query.first()