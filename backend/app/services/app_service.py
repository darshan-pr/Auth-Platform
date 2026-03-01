from sqlalchemy.orm import Session
from ..models import app as app_model


def create_app(db: Session, app_data: dict):
    new_app = app_model.App(**app_data)
    db.add(new_app)
    db.commit()
    db.refresh(new_app)
    return new_app


def get_apps_by_tenant(db: Session, tenant_id: int):
    return db.query(app_model.App).filter(
        app_model.App.tenant_id == tenant_id
    ).all()


def get_app_by_id(db: Session, app_id: str, tenant_id: int = None):
    query = db.query(app_model.App).filter(app_model.App.app_id == app_id)
    if tenant_id:
        query = query.filter(app_model.App.tenant_id == tenant_id)
    return query.first()