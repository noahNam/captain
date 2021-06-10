from flask import g
from pubsub import pub

from core.domains.authentication.dto.authentication_dto import GetBlacklistDto
from core.domains.authentication.enum import AuthenticationTopicEnum
from core.domains.authentication.repository.authentication_repository import (
    AuthenticationRepository,
)
from core.domains.user.dto.user_dto import GetUserDto


def create_or_update_token(dto: GetUserDto) -> None:
    AuthenticationRepository().create_or_update_token(dto=dto)
    token_info = AuthenticationRepository().get_token_info_by_dto(dto=dto)
    # to redis
    AuthenticationRepository().set_token_to_cache(token_info=token_info)

    setattr(g, AuthenticationTopicEnum.CREATE_OR_UPDATE_TOKEN, token_info)


def create_blacklist(dto: GetBlacklistDto) -> None:
    AuthenticationRepository().create_blacklist(dto=dto)
    blacklist_info = AuthenticationRepository().get_blacklist_by_dto(dto=dto)
    # to redis
    AuthenticationRepository().set_blacklist_to_cache(blacklist_info)

    setattr(g, AuthenticationTopicEnum.CREATE_BLACKLIST, blacklist_info)


pub.subscribe(create_or_update_token, AuthenticationTopicEnum.CREATE_OR_UPDATE_TOKEN)
pub.subscribe(create_blacklist, AuthenticationTopicEnum.CREATE_BLACKLIST)
