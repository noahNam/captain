from flask import url_for
from flask_jwt_extended import create_access_token

from app.persistence.model.user_model import UserModel
from core.use_case_output import FailureType


def test_when_get_user_with_valid_user_id_then_success(
    client, session, test_request_context, jwt_manager, make_header
):
    user = UserModel(nickname="Tester")
    session.add(user)
    session.commit()

    access_token = create_access_token(identity=user.id)
    authorization = "Bearer " + access_token
    headers = make_header(authorization=authorization)

    with test_request_context:
        response = client.get(
            url_for("api/widow.get_user_view", user_id=user.id),
            headers=headers,
        )

    assert response.status_code == 200
    data = response.get_json()["data"]
    assert data["user"]["id"] == user.id


def test_when_get_not_existing_user_then_failure(
    client, session, test_request_context, jwt_manager, make_header
):
    user = UserModel(nickname="Tester")
    session.add(user)
    session.commit()

    access_token = create_access_token(identity=user.id)
    authorization = "Bearer " + access_token
    headers = make_header(authorization=authorization)

    with test_request_context:
        response = client.get(
            url_for("api/widow.get_user_view", user_id=0),
            headers=headers,
        )

    assert response.status_code == 400
    assert response.get_json()["type"] == FailureType.NOT_FOUND_ERROR
