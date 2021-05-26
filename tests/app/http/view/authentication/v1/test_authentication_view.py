from flask import url_for


def test_update_view(client, test_request_context, make_header, make_authorization):
    user_id = 1
    authorization = make_authorization(user_id=user_id)
    headers = make_header(authorization=authorization)

    with test_request_context:
        response = client.get(
            url_for("api.token_update_view"), headers=headers
        )

    d = response.get_json()
