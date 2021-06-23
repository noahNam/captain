from pydantic import BaseModel


class ResponseOAuthSchema(BaseModel):
    access_token: str
