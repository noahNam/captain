import random

import factory
from faker import Factory as FakerFactory
from app.persistence.model.user_model import UserModel

# factory에 사용해야 하는 Model을 가져온다
faker = FakerFactory.create(locale="ko_KR")

provider = ["kakao", "naver"]


class BaseFactory(factory.alchemy.SQLAlchemyModelFactory):
    class Meta(object):
        abstract = True


class UserFactory(BaseFactory):
    """
    Define user factory
    """

    class Meta:
        model = UserModel

    provider = random.choice(provider)
    provider_id = factory.Sequence(lambda n: n + 1)
