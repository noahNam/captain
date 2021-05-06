from dataclasses import dataclass

from pydantic import BaseModel


@dataclass
class UserEntity(BaseModel):
    id: int = None
    provider: str = None
    provider_id: int = None
    group: str = None
