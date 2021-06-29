from pydantic import BaseModel, StrictInt, StrictBytes


class JwtDto(BaseModel):
    token: StrictBytes = None


class GetBlacklistDto(BaseModel):
    user_id: StrictInt = None
    access_token: str = None
