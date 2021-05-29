from typing import Optional
from app import redis
from app.extensions.database import session
from app.extensions.utils.log_helper import logger_
from app.extensions.utils.time_helper import (get_jwt_access_expired_timestamp,
                                              get_jwt_refresh_expire_timedelta_to_seconds,
                                              get_jwt_access_expire_timedelta_to_seconds,
                                              get_jwt_refresh_expired_timestamp)
from app.persistence.model import BlacklistModel
from app.persistence.model.jwt_model import JwtModel
from core.domains.authentication.dto.authentication_dto import GetBlacklistDto
from core.domains.authentication.entity.blacklist_entity import BlacklistEntity
from core.domains.authentication.entity.jwt_entity import JwtEntity
from core.domains.user.dto.user_dto import GetUserDto
from flask_jwt_extended import create_access_token, create_refresh_token

logger = logger_.getLogger(__name__)


class AuthenticationRepository:
    def _is_exists(self, dto: GetUserDto) -> bool:
        """
            기존 유저 토큰 존재 여부
        """
        if session.query(JwtModel).filter_by(user_id=dto.user_id).first():
            return True
        return False

    def _update_token(self, dto: GetUserDto) -> None:
        """
            새로운 Token 생성
            update 시간 갱신
        """
        try:
            session.query(JwtModel).filter_by(user_id=dto.user_id) \
                .update(
                {
                    "access_token": create_access_token(identity=dto.user_id),
                    "refresh_token": create_refresh_token(identity=dto.user_id),
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

    def _create_token(self, dto: GetUserDto) -> None:
        token_info = JwtModel(
            user_id=dto.user_id,
            access_token=create_access_token(identity=dto.user_id),
            refresh_token=create_refresh_token(identity=dto.user_id),
        )

        try:
            session.add(token_info)
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(
                f"[AuthenticationRepository][create_token] user_id : {dto.user_id} "
                f"error : {e}"
            )

    def create_or_update_token(self, dto: GetUserDto) -> None:
        """
            case 1: 신규 회원가입 -> Create
            case 2: 기존 유저가 로그아웃 후 재로그인 -> Update
        """
        if self._is_exists(dto=dto):
            # 현재 시간 기준 업데이트
            self._update_token(dto=dto)
        else:
            self._create_token(dto=dto)

    def get_token_info_by_dto(self, dto: GetUserDto) -> Optional[JwtEntity]:
        token_info = session.query(JwtModel).filter_by(user_id=dto.user_id).first()

        if not token_info:
            return None
        return token_info.to_entity()

    def get_token_info_by_user_id(self, user_id: int) -> Optional[JwtEntity]:
        token_info = session.query(JwtModel).filter_by(user_id=user_id).first()

        if not token_info:
            return None
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
        """
            Save Token_info to Redis (key : value)
            - jwt_access_token : user_id
            - user_id : jwt_refresh_token
        """
        if redis.is_available() and token_info:
            self._set_access_token_to_cache(token_info)
            self._set_refresh_token_to_cache(token_info)

            return True
        return False

    def create_blacklist(self, dto: GetBlacklistDto) -> None:
        blacklist = BlacklistModel(user_id=dto.user_id,
                                   access_token=dto.access_token)
        try:
            session.add(blacklist)
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(
                f"[AuthenticationRepository][create_blacklist] user_id : {dto.user_id}, "
                f"access_token : {dto.access_token} error : {e}"
            )

    def get_blacklist_by_dto(self, dto: GetBlacklistDto) -> Optional[BlacklistEntity]:
        blacklist = session.query(BlacklistModel).filter_by(user_id=dto.user_id).first()

        if not blacklist:
            return None
        return blacklist.to_entity()

    def get_blacklist_by_user_id(self, user_id: int) -> Optional[BlacklistEntity]:
        blacklist = session.query(JwtModel).filter_by(user_id=user_id).first()

        if not blacklist:
            return None
        return blacklist.to_entity()

    def delete_blacklist(self, dto: GetBlacklistDto) -> None:
        blacklist = BlacklistModel(user_id=dto.user_id,
                                   access_token=dto.access_token)
        try:
            session.delete(blacklist)
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(
                f"[AuthenticationRepository][delete_blacklist] user_id : {dto.user_id}, "
                f"access_token : {dto.access_token} error : {e}"
            )

    def set_blacklist_to_cache(self, blacklist_info: Optional[BlacklistEntity]) -> None:
        try:
            set_name = "jwt_blacklist"
            value = blacklist_info.access_token
            # 집합 set 에 blacklist_token 추가
            redis.sadd(set_name=set_name, values=value)
            # 집합에 만료시간 지정 (30분)
            redis.expire(key=set_name, time=get_jwt_access_expire_timedelta_to_seconds())
        except Exception as e:
            logger.error(
                f"[AuthenticationRepository][set_access_token_to_cache] key : {blacklist_info.access_token}, "
                f"value : {blacklist_info.user_id} error : {e}"
            )

