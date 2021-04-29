from pydantic import BaseModel


class UserEntity(BaseModel):
    id: int = None
    nickname: str = None
    status: str = None
    sex: str = None
