KAKAO_API_BASE_URL = "https://kauth.kakao.com"
KAKAO_AUTHORIZE_END_POINT = "/oauth/authorize"
KAKAO_GET_ACCESS_TOKEN_END_POINT = "/oauth/token"
KAKAO_REDIRECT_URL = "http://127.0.0.1:5000/api/captain/v1/oauth/kakao"
GRANT_TYPE = "authorization_code"

request_default_header = {
    "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
    "Cache-Control": "no-cache",
}
