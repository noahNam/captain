from dataclasses import dataclass
from datetime import datetime


@dataclass
class PostEntity:
    id: int = None
    user_id: int = None
    title: str = None
    body: str = None
    created_at: datetime = None
    updated_at: datetime = None
