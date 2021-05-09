from pydantic import BaseModel, StrictInt, StrictStr


class UserResponseSchema(BaseModel):
    id: StrictInt
    nickname: StrictStr
