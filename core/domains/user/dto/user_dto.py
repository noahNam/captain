from pydantic import BaseModel


class GetUserDto(BaseModel):
    user_id: int = None
