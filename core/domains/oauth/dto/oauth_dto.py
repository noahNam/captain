from pydantic import BaseModel


class GetOAuthDto(BaseModel):
    provider: str = None
