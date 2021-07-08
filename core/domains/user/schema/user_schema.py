from pydantic import BaseModel, StrictInt, StrictStr


class UserResponseSchema(BaseModel):
    id: StrictInt
    provider: StrictStr
    provider_id: StrictInt


class GetUserProviderResponseSchema(BaseModel):
    provider: StrictStr
