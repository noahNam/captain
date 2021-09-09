from pydantic import BaseModel, StrictInt, StrictBytes


class JwtDto(BaseModel):
    token: StrictBytes = None


class GetUserDto(BaseModel):
    user_id: int


class GetBlacklistDto(BaseModel):
    user_id: StrictInt = None
    access_token: str = None


class JwtWithUUIDDto(BaseModel):
    token: StrictBytes = None
    uuid: str
