from pydantic import BaseModel, StrictInt, StrictStr


class UserResponseSchema(BaseModel):
    id: StrictInt
    provider: StrictStr
    provider_id: StrictStr


class GetUserProviderResponseSchema(BaseModel):
    provider: StrictStr
