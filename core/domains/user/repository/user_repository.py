from typing import Optional

from sqlalchemy.sql import exists
from app.extensions.database import session
from app.extensions.utils.log_helper import logger_
from app.persistence.model.user_model import UserModel
from core.domains.user.dto.user_dto import CreateUserDto
from core.domains.user.entity.user_entity import UserEntity

logger = logger_.getLogger(__name__)


class UserRepository:
    def create_user(self, dto: CreateUserDto) -> None:
        if session.query(
            exists()
            .where(UserModel.provider == dto.provider)
            .where(UserModel.provider_id == dto.provider_id)
        ).scalar():
            return

        try:
            user = UserModel(provider=dto.provider, provider_id=dto.provider_id,)
            session.add(user)
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(
                f"[UserRepository][create_user] provider : {dto.provider} "
                f"provider_id : {dto.provider_id} error : {e}"
            )

    def get_user_by_user_id(self, user_id: int) -> Optional[UserEntity]:
        user = session.query(UserModel).filter_by(id=user_id).first()

        if not user:
            return None
        return user.to_entity()

    def get_user_by_create_user_dto(self, dto: CreateUserDto) -> Optional[UserEntity]:
        user = (
            session.query(UserModel)
            .filter_by(provider=dto.provider, provider_id=dto.provider_id)
            .first()
        )

        if not user:
            return None
        return user.to_entity()
