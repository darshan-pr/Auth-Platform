from sqlalchemy.orm import Session
from ..models import app as app_model

def create_app(db: Session, app_data: dict):
    new_app = app_model.App(**app_data)
    db.add(new_app)
    db.commit()
    db.refresh(new_app)
    return new_app