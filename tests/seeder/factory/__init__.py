import random
from datetime import datetime

import factory
import jwt
from faker import Factory as FakerFactory

from app.extensions.utils.time_helper import get_jwt_access_expired_timestamp, get_jwt_refresh_expired_timestamp
from app.persistence.model.jwt_model import JwtModel
from app.persistence.model.user_model import UserModel

from core.domains.oauth.enum.oauth_enum import ProviderEnum

# factory에 사용해야 하는 Model을 가져온다

faker = FakerFactory.create(locale="ko_KR")
provider_list = tuple([provider.value for provider in list(ProviderEnum)])


def make_custom_jwt(obj: any, exp: datetime) -> bytes:
    payload = {
        "user_id": str(obj),
        "exp": exp
    }
    custom_secret_key = "hawaii"
    encrypt_algorithm = "HS256"
    return jwt.encode(payload=payload,
                      key=custom_secret_key,
                      algorithm=encrypt_algorithm)


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
    access_token = make_custom_jwt(factory.Sequence(lambda n: n + 1), get_jwt_access_expired_timestamp())
    refresh_token = make_custom_jwt(factory.Sequence(lambda n: n + 1), get_jwt_refresh_expired_timestamp())
    access_expired_at = get_jwt_access_expired_timestamp()
    refresh_expired_at = get_jwt_refresh_expired_timestamp()


class UserFactory(BaseFactory):
    """
    Define user factory
    """

    class Meta:
        model = UserModel

    provider = random.choice(provider_list)
    provider_id = factory.Sequence(lambda n: n + 1)

    jwt_models = factory.List([factory.SubFactory(JwtFactory)])
