from pydantic import BaseModel


class GetUserDto(BaseModel):
    user_id: int = None


class CreateUserDto(BaseModel):
    provider: str
    provider_id: int
