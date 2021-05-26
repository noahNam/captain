from pydantic import BaseModel


class UpdateJwtResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
