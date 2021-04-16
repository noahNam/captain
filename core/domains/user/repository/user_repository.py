from typing import Optional

from app.extensions.database import session
from app.persistence.model.user_model import UserModel
from core.domains.user.entity.user_entity import UserEntity


class UserRepository:
    def get_user(self, user_id: int) -> Optional[UserEntity]:
        user = session.query(UserModel).filter_by(id=user_id).first()

        if not user:
            return
        return user.to_entity()
