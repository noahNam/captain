from pydantic import BaseModel


class GetOAuthProviderDto(BaseModel):
    provider: str = None



