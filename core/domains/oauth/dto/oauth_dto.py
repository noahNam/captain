from pydantic import BaseModel


class GetOAuthProviderDto(BaseModel):
    provider: str = None


class CreateUserDto(BaseModel):
    provider: str = None
    provider_id: int = None
