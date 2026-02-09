from pydantic import BaseModel

class AppCreateRequest(BaseModel):
    name: str
    description: str = None

class AppResponse(BaseModel):
    id: int
    name: str
    description: str = None