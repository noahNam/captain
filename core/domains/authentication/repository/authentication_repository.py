from typing import Optional

from app import redis
from app.extensions.database import session
from app.extensions.utils.log_helper import logger_
from app.extensions.utils.time_helper import get_jwt_access_expired_timestamp, get_jwt_refresh_expired_timestamp, \
    get_jwt_access_expire_timedelta_to_seconds, get_jwt_refresh_expire_timedelta_to_seconds
from app.persistence.model.jwt_model import JwtModel
from core.domains.authentication.entity.jwt_entity import JwtEntity
from core.domains.user.dto.user_dto import GetUserDto
from flask_jwt_extended import create_access_token, create_refresh_token

logger = logger_.getLogger(__name__)


class AuthenticationRepository:
    def _is_exists(self, dto: GetUserDto) -> bool:
        """
            기존 유저 존재 여부
        """
        if session.query(JwtModel).filter_by(user_id=dto.user_id).first():
            return True
        return False

    def _update_token(self, dto: GetUserDto, token_info: JwtModel) -> None:
        try:
            session.query(JwtModel).filter_by(user_id=dto.user_id) \
                .update(
                {
                    "access_token": token_info.access_token,
                    "refresh_token": token_info.refresh_token,
                    "access_expired_at": get_jwt_access_expired_timestamp(),
                    "refresh_expired_at": get_jwt_refresh_expired_timestamp()
                }
            )
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(
                f"[AuthenticationRepository][update_token] user_id : {dto.user_id} "
                f"error : {e}"
            )

    def _create_token(self, dto: GetUserDto, token_info: JwtModel) -> None:
        try:
            session.add(token_info)
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(
                f"[AuthenticationRepository][create_token] user_id : {dto.user_id} "
                f"error : {e}"
            )

    def create_or_update_token(self, dto: GetUserDto) -> Optional[JwtEntity]:
        """
            case 1: 신규 회원가입 -> Create
            case 2: 기존 유저가 로그아웃 후 재로그인 -> Update
        """
        token_info = JwtModel(
            user_id=dto.user_id,
            access_token=create_access_token(identity=dto.user_id),
            refresh_token=create_refresh_token(identity=dto.user_id)
        )

        if self._is_exists(dto=dto):
            self._update_token(dto=dto, token_info=token_info)
        else:
            self._create_token(dto=dto, token_info=token_info)

        return token_info.to_entity()

    def _set_access_token_to_cache(self, token_info: Optional[JwtEntity]):
        try:
            redis.set(
                key=token_info.access_token,
                value=token_info.user_id,
                ex=get_jwt_access_expire_timedelta_to_seconds()
            )
        except Exception as e:
            logger.error(
                f"[AuthenticationRepository][set_access_token_to_cache] key : {token_info.access_token}, "
                f"value : {token_info.user_id} error : {e}"
            )

    def _set_refresh_token_to_cache(self, token_info: Optional[JwtEntity]):
        try:
            redis.set(
                key=token_info.user_id,
                value=token_info.refresh_token,
                ex=get_jwt_refresh_expire_timedelta_to_seconds()
            )
        except Exception as e:
            logger.error(
                f"[AuthenticationRepository][set_refresh_token_to_cache] key : {token_info.user_id}, "
                f"value : {token_info.refresh_token} error : {e}"
            )

    def set_token_to_cache(self, token_info: Optional[JwtEntity]) -> bool:
        if token_info:
            self._set_access_token_to_cache(token_info)
            self._set_refresh_token_to_cache(token_info)

            return True
        return False
