from dataclasses import dataclass
from datetime import datetime


@dataclass
class JwtEntity:
    id: int
    user_id: int
    access_token: str
    refresh_token: str
    access_expired_at: datetime
    refresh_expired_at: datetime
