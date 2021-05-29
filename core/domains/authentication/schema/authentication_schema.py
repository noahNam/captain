from pydantic import BaseModel


class UpdateJwtResponseSchema(BaseModel):
    access_token: str


class LogoutResponseSchema(BaseModel):
    blacklist_token: str
    expired_at: str
