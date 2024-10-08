from typing import Optional

from sqlalchemy.sql import exists

from app import redis
from app.extensions.database import session
from app.extensions.utils.log_helper import logger_
from app.extensions.utils.time_helper import (
    get_server_timestamp,
    get_jwt_refresh_expire_timedelta_to_seconds,
)
from app.persistence.model.user_model import UserModel
from core.domains.user.dto.user_dto import CreateUserDto, GetUserProviderDto
from core.domains.user.entity.user_entity import UserEntity
from core.domains.user.enum.user_enum import UserGroupEnum

logger = logger_.getLogger(__name__)


class UserRepository:
    def update_user_uuid(self, dto: CreateUserDto) -> None:
        """
            기존 사용자 로그인시 UUID를 갱신한다
        """
        try:
            session.query(UserModel).filter_by(
                provider=dto.provider, provider_id=dto.provider_id
            ).update(
                {
                    "provider": dto.provider,
                    "provider_id": dto.provider_id,
                    "uuid": dto.uuid,
                }
            )
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(
                f"[UserRepository][update_user_uuid] provider: {dto.provider}, "
                f"provider_id: {dto.provider_id}, uuid: {dto.uuid} error : {e}"
            )

    def is_exists_user(self, provider_id: str, provider: str) -> bool:
        query = session.query(
            exists()
            .where(UserModel.provider == provider)
            .where(UserModel.provider_id == provider_id)
        )
        if query.scalar():
            return True
        return False

    def is_exists_user_by_user_id(self, user_id: int) -> bool:
        query = session.query(exists().where(UserModel.id == user_id))
        if query.scalar():
            return True
        return False

    def create_user(self, dto: CreateUserDto) -> None:
        """
            신규가입 사용자 -> DB 저장
        """
        try:
            user = UserModel(
                provider=dto.provider,
                provider_id=dto.provider_id,
                uuid=dto.uuid,
                group=UserGroupEnum.USER.value,
            )
            session.add(user)
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(
                f"[UserRepository][create_user] provider : {dto.provider} "
                f"provider_id : {dto.provider_id} "
                f"uuid : {dto.uuid} error : {e}"
            )

    def get_user_by_user_id(self, user_id: int) -> Optional[UserEntity]:
        user = session.query(UserModel).filter_by(id=user_id).first()

        if not user:
            return None
        return user.to_entity()

    def get_user_by_create_user_dto(self, dto: CreateUserDto) -> Optional[UserEntity]:
        user = (
            session.query(UserModel)
            .filter_by(
                provider=dto.provider, provider_id=dto.provider_id, uuid=dto.uuid
            )
            .first()
        )

        if not user:
            return None
        return user.to_entity()

    def set_user_uuid_to_cache(self, user_id: int, uuid: str) -> bool:
        """
            Save UUID to Redis (key : value)
            - UUID : user_id
        """
        try:
            redis.set(
                key=uuid,
                value=user_id,
                ex=get_jwt_refresh_expire_timedelta_to_seconds(),
            )
            return True
        except Exception as e:
            logger.error(
                f"[AuthenticationRepository][set_user_uuid_to_cache] key : {uuid}, "
                f"value : {user_id} error : {e}"
            )
            return False

    def is_valid_user_uuid_from_redis(self, uuid: str, user_id: int) -> bool:
        # user_id_value : bytes type from redis
        user_id_value = redis.get_by_key(key=uuid)
        if user_id_value != str(user_id).encode("UTF-8"):
            return False
        return True

    def is_valid_user_uuid(self, uuid: str, user_id: int) -> bool:
        user_info = session.query(UserModel).filter_by(id=user_id).first()
        if user_info.uuid != uuid:
            return False
        return True

    def get_user_provider(self, dto: GetUserProviderDto) -> str:
        user = session.query(UserModel).filter_by(id=dto.user_id).first()

        return user.provider

    def update_current_connection_time(self, user_id: int) -> None:
        """
            최근 접속 일자
        """
        try:
            session.query(UserModel).filter_by(id=user_id).update(
                {"current_connection_time": get_server_timestamp()}
            )
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(
                f"[UserRepository][update_current_connection_time] user_id : {user_id} "
                f"error : {e}"
            )
