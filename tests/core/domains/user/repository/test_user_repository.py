from app.persistence.model.user_model import UserModel
from core.domains.user.repository.user_repository import UserRepository


def test_create_user_when_not_use_factory_boy(session):
    user = UserModel(nickname="Noah")
    session.add(user)
    session.commit()

    result = session.query(UserModel).first()

    assert result.nickname == user.nickname


def test_get_user(session):
    user = UserModel(nickname="Tester")
    session.add(user)
    session.commit()

    user_entity = UserRepository().get_user(user_id=user.id)

    assert user_entity == user.to_entity()
