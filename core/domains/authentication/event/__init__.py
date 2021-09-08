from typing import Optional

from flask import g
from pubsub import pub

from core.domains.authentication.dto.authentication_dto import GetBlacklistDto
from core.domains.authentication.entity.jwt_entity import JwtEntity
from core.domains.authentication.enum import AuthenticationTopicEnum
from core.domains.authentication.repository.authentication_repository import (
    AuthenticationRepository,
)
from core.domains.user.dto.user_dto import GetUserDto


def is_exists_token(dto: GetUserDto) -> None:
    is_jwt_exists = AuthenticationRepository().is_exists_token(dto=dto)
    setattr(g, AuthenticationTopicEnum.IS_EXISTS_TOKEN, is_jwt_exists)


def create_token(dto: GetUserDto) -> None:
    AuthenticationRepository().create_token(dto=dto)
    setattr(g, AuthenticationTopicEnum.CREATE_TOKEN, None)


def update_token(dto: GetUserDto) -> None:
    AuthenticationRepository().update_token(dto=dto)
    setattr(g, AuthenticationTopicEnum.UPDATE_TOKEN, None)


def get_token_info(dto: GetUserDto) -> None:
    token_info = AuthenticationRepository().get_token_info_by_dto(dto=dto)
    setattr(g, AuthenticationTopicEnum.GET_TOKEN_INFO, token_info)


def set_token_to_cache(token_info: Optional[JwtEntity]) -> None:
    # set to redis
    result = AuthenticationRepository().set_token_to_cache(token_info=token_info)
    setattr(g, AuthenticationTopicEnum.SET_TOKEN_TO_CACHE, result)


def create_blacklist(dto: GetBlacklistDto) -> None:
    AuthenticationRepository().create_blacklist(dto=dto)
    blacklist_info = AuthenticationRepository().get_blacklist_by_dto(dto=dto)
    # set to redis
    AuthenticationRepository().set_blacklist_to_cache(blacklist_info)

    setattr(g, AuthenticationTopicEnum.CREATE_BLACKLIST, blacklist_info)


def is_redis_ready() -> None:
    is_redis_ready = AuthenticationRepository().is_redis_ready()
    setattr(g, AuthenticationTopicEnum.IS_REDIS_READY, is_redis_ready)


pub.subscribe(is_exists_token, AuthenticationTopicEnum.IS_EXISTS_TOKEN)
pub.subscribe(create_token, AuthenticationTopicEnum.CREATE_TOKEN)
pub.subscribe(update_token, AuthenticationTopicEnum.UPDATE_TOKEN)
pub.subscribe(get_token_info, AuthenticationTopicEnum.GET_TOKEN_INFO)
pub.subscribe(create_blacklist, AuthenticationTopicEnum.CREATE_BLACKLIST)
pub.subscribe(set_token_to_cache, AuthenticationTopicEnum.SET_TOKEN_TO_CACHE)
pub.subscribe(is_redis_ready, AuthenticationTopicEnum.IS_REDIS_READY)
