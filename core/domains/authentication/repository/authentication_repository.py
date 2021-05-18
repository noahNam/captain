from typing import Optional

from sqlalchemy import exc

from app.extensions.database import session
from app.extensions.utils.log_helper import logger_
from app.persistence.model.jwt_model import JwtModel
from core.domains.authentication.entity.jwt_entity import JwtEntity
from core.domains.user.dto.user_dto import GetUserDto
from flask_jwt_extended import create_access_token, create_refresh_token

logger = logger_.getLogger(__name__)


class AuthenticationRepository:
    def create_token(self, dto=GetUserDto) -> Optional[JwtEntity]:
        token_info = None
        try:
            token_info = JwtModel(
                user_id=dto.user_id,
                access_token=create_access_token(identity=dto.user_id),
                refresh_token=create_refresh_token(identity=dto.user_id)
            )
            session.add(token_info)
            session.commit()
        except exc.IntegrityError as e:
            session.rollback()
            logger.error(
                f"[AuthenticationRepository][create_token] user_id : {dto.user_id} "
                f"error : {e}"
            )

        return token_info.to_entity()

    def set_token_to_cache(self, dto):
        pass
