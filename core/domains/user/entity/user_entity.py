from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class UserEntity(BaseModel):
    id: int
    uuid: Optional[str]
    provider: str
    provider_id: str
    group: Optional[str]
    created_at: datetime
    updated_at: datetime
