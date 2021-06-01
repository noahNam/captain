from pydantic import BaseModel


class GetUserDto(BaseModel):
    user_id: int


class CreateUserDto(BaseModel):
    provider: str
    provider_id: str
