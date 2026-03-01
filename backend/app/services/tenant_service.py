import re
from sqlalchemy.orm import Session
from app.models.tenant import Tenant


def create_tenant(db: Session, name: str) -> Tenant:
    """Create a new tenant with auto-generated slug"""
    slug = _generate_slug(name)

    # Ensure slug uniqueness
    existing = db.query(Tenant).filter(Tenant.slug == slug).first()
    counter = 1
    base_slug = slug
    while existing:
        slug = f"{base_slug}-{counter}"
        existing = db.query(Tenant).filter(Tenant.slug == slug).first()
        counter += 1

    tenant = Tenant(name=name, slug=slug)
    db.add(tenant)
    db.flush()  # Get the ID without committing
    return tenant


def get_tenant_by_id(db: Session, tenant_id: int) -> Tenant:
    return db.query(Tenant).filter(Tenant.id == tenant_id).first()


def get_or_create_default_tenant(db: Session) -> Tenant:
    """Get or create the default tenant (used for legacy flows)"""
    tenant = db.query(Tenant).filter(Tenant.slug == "default").first()
    if not tenant:
        tenant = Tenant(name="Default", slug="default")
        db.add(tenant)
        db.flush()
    return tenant


def _generate_slug(name: str) -> str:
    """Generate a URL-friendly slug from a name"""
    slug = name.lower().strip()
    slug = re.sub(r'[^a-z0-9\s-]', '', slug)
    slug = re.sub(r'[\s]+', '-', slug)
    slug = re.sub(r'-+', '-', slug)
    return slug.strip('-')
