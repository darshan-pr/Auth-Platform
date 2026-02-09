from sqlalchemy.orm import Session
from ..models import user as user_model

def create_user(db: Session, user_data: dict):
    new_user = user_model.User(**user_data)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

def get_user_by_email(db: Session, email: str):
    return db.query(user_model.User).filter(user_model.User.email == email).first()