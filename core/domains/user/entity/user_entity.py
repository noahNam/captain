from datetime import timezone

from pydantic import BaseModel
from pydantic.datetime_parse import datetime


class UserEntity(BaseModel):
    id: int = None
    provider: str = None
    provider_id: int = None
    group: str = None
    created_at: datetime = datetime.now(timezone.utc)
    updated_at: datetime = None
