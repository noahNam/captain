import random
from uuid import uuid4
from datetime import datetime, timedelta
from typing import Optional

import factory
import jwt
from faker import Factory as FakerFactory

from app.extensions.utils.time_helper import (
    get_jwt_access_expired_timestamp,
    get_jwt_refresh_expired_timestamp,
    get_server_timestamp,
    get_jwt_access_expired_time_delta,
    get_jwt_refresh_expired_time_delta,
)
from app.persistence.model import BlacklistModel
from app.persistence.model.jwt_model import JwtModel
from app.persistence.model.user_model import UserModel

from core.domains.oauth.enum.oauth_enum import ProviderEnum

# factory에 사용해야 하는 Model을 가져온다

faker = FakerFactory.create(locale="ko_KR")
provider_list = tuple([provider.value for provider in list(ProviderEnum)])


def make_custom_jwt(
    obj: any,
    token_type: Optional[str] = None,
    now: Optional[datetime] = None,
    delta: Optional[timedelta] = None,
) -> bytes:
    uid = str(uuid4())
    if not now:
        now = datetime.utcnow()
    if not delta:
        delta = get_jwt_access_expired_time_delta()
    payload = {
        # additional info
        "identity": str(obj),
        "fresh": False,
        "type": token_type,
        # basic info
        "iat": now,
        "nbf": now,
        "jti": uid,
        "exp": now + delta,
    }

    custom_secret_key = "hawaii"
    encrypt_algorithm = "HS256"
    return jwt.encode(
        payload=payload, key=custom_secret_key, algorithm=encrypt_algorithm
    )


class BaseFactory(factory.alchemy.SQLAlchemyModelFactory):
    class Meta(object):
        abstract = True


class JwtFactory(BaseFactory):
    """
    Define JwtModel factory
    """

    pass

    class Meta:
        model = JwtModel

    user_id = factory.Sequence(lambda n: n + 1)
    access_token = make_custom_jwt(
        user_id,
        token_type="access",
        now=get_server_timestamp(),
        delta=get_jwt_access_expired_time_delta(),
    )
    refresh_token = make_custom_jwt(
        user_id,
        token_type="refresh",
        now=get_server_timestamp(),
        delta=get_jwt_refresh_expired_time_delta(),
    )
    access_expired_at = get_jwt_access_expired_timestamp()
    refresh_expired_at = get_jwt_refresh_expired_timestamp()


class BlacklistFactory(BaseFactory):
    """
        Define blacklist factory
    """

    class Meta:
        model = BlacklistModel

    user_id = factory.Sequence(lambda n: n + 1)
    access_token = make_custom_jwt(
        user_id,
        token_type="access",
        now=get_server_timestamp(),
        delta=get_jwt_access_expired_time_delta(),
    )


class UserBaseFactory(BaseFactory):
    """
        Define user base factory
    """

    class Meta:
        model = UserModel

    provider = random.choice(provider_list)
    provider_id = factory.Sequence(lambda n: n + 1)
    uuid = str(uuid4())


class UserFactory(UserBaseFactory):
    """
        Define user factory with jwt_models
    """

    jwt_models = factory.List([factory.SubFactory(JwtFactory)])


class InvalidJwtFactory(BaseFactory):
    """
    Define invalid JwtModel factory (made yesterday)
    """

    class Meta:
        model = JwtModel

    user_id = factory.Sequence(lambda n: n + 1)
    access_token = make_custom_jwt(
        obj=user_id,
        token_type="access",
        now=datetime.now() - timedelta(days=1),
        delta=get_jwt_access_expired_time_delta(),
    )
    refresh_token = make_custom_jwt(
        obj=user_id,
        token_type="refresh",
        now=datetime.now() - timedelta(days=1),
        delta=get_jwt_refresh_expired_time_delta(),
    )
    access_expired_at = (
        datetime.now() - timedelta(days=1) + get_jwt_access_expired_time_delta()
    )
    refresh_expired_at = (
        datetime.now() - timedelta(days=1) + get_jwt_refresh_expired_time_delta()
    )
