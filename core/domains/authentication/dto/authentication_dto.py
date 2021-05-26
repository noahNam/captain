from pydantic import BaseModel, StrictInt, StrictBytes


class UpdateJwtDto(BaseModel):
    token: StrictBytes = None


class GetBlacklistDto(BaseModel):
    user_id: StrictInt = None
    access_token: StrictBytes = None
