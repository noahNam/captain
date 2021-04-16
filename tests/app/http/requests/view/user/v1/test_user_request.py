from app.http.requests.view.user.v1.user_request import GetUserRequest


def test_when_invalid_request_then_fail():
    result = GetUserRequest(user_id="invalid user id").validate_request_and_make_dto()

    assert result is False
