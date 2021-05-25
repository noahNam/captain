from dataclasses import dataclass
from datetime import datetime


@dataclass
class BlacklistEntity:
    id: int
    user_id: int
    access_token: str
    expired_at: datetime
