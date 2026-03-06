from sqlalchemy.orm import Session
from ..models import user as user_model


def create_user(db: Session, user_data: dict):
    new_user = user_model.User(**user_data)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


def get_user_by_email(db: Session, email: str, app_id: str = None, tenant_id: int = None):
    """Get user by email, scoped by app_id and tenant_id for proper isolation"""
    query = db.query(user_model.User).filter(user_model.User.email == email)
    if tenant_id:
        query = query.filter(user_model.User.tenant_id == tenant_id)
    if app_id:
        query = query.filter(user_model.User.app_id == app_id)
    return query.first()


def get_users_by_tenant(db: Session, tenant_id: int, skip: int = 0, limit: int = 100):
    return db.query(user_model.User).filter(
        user_model.User.tenant_id == tenant_id
    ).offset(skip).limit(limit).all()