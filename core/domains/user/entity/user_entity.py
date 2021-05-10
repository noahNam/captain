from dataclasses import dataclass
from datetime import datetime


@dataclass
class UserEntity:
    id: int
    provider: str
    provider_id: int
    group: str
    created_at: datetime
    updated_at: datetime
