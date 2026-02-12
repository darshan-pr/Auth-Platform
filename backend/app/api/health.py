from fastapi import APIRouter

router = APIRouter()

@router.get("/")
@router.get("/health")
def health_check():
    return {"status": "healthy"}