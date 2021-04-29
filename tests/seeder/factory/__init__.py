import factory
from faker import Factory as FakerFactory
from app.persistence.model.user_model import UserModel

# factory에 사용해야 하는 Model을 가져온다
faker = FakerFactory.create(locale="ko_KR")


class UserFactory(factory.alchemy.SQLAlchemyModelFactory):
    """
    Define user factory
    """

    class Meta:
        model = UserModel

    nickname = factory.Sequence(lambda n: "test_user_{}".format(n))
    status = "default"
    sex = "M"
