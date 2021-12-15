import time
from starlette.requests import Request
from starlette.datastructures import URL, Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send
from common import config, consts
from models import UserToken
from utils.date_utils import D
from errors.exceptions import APIException
from errors import exceptions as ex
import typing
import re
from jwt.exceptions import ExpiredSignatureError, DecodeError
import jwt
from common.consts import EXCEPT_PATH_LIST, EXCEPT_PATH_REGEX
from utils.logger import api_logger


async def access_control(request: Request, call_next):
    request.state.req_time = D.datetime()
    request.state.start = time.time()
    request.state.inspect = None
    request.state.user = None
    ip = request.headers["x-forwarded-for"] if "x-forwarded-for" in request.headers.keys() else request.client.host
    request.state.ip = ip.split(",")[0] if "," in ip else ip
    headers = request.headers
    cookies = request.cookies
    url = request.url.path

    if await url_pattern_check(url, EXCEPT_PATH_REGEX) or url in EXCEPT_PATH_LIST:
        response = await call_next(request)
        if url != "/":
            await api_logger(request=request, response=response)
        return response

    try:
        if url.startswith("/api"):
            # api 인경우 헤더로 토큰 검사
            if "authorization" in headers.keys():
                token_info = await token_decode(access_token=headers.get("Authorization"))
                request.state.user = UserToken(**token_info)

            else:
                if "Authorization" not in headers.keys():
                    raise ex.NotAuthorized()

        else:
            # 템플릿 랜더링인 경우 쿠키에서 토큰 검사
            cookies["Authorization"] = "Bearer token!!"

            if "Authorization" not in cookies.keys():
                raise ex.NotAuthorized

            token_info = await call_next(request)
            request.state.user = UserToken(**token_info)

        response = await call_next(request)
        await api_logger(request=request, response=response)

    except Exception as e:
        error = await exception_handler(e)
        error_dict = dict(status=error.status_code, msg=error.msg, detail=error.detail, code=error.code)
        response = JSONResponse(status_code=error.status_code, content=error_dict)
        await api_logger(request, error=error)

    return response


#
#
#
#
# class AccessControl:
#     def __init__(
#             self,
#             app: ASGIApp,
#             except_path_list: typing.Sequence[str] = None,
#             except_path_regex: str = None,
#     ) -> None:
#         if except_path_list is None:
#             except_path_list = ["*"]
#         self.app = app
#         self.except_path_list = except_path_list
#         self.except_path_regex = except_path_regex
#
#     async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
#         request = Request(scope=scope)
#         headers = Headers(scope=scope)
#
#         request.state.start = time.time()
#         request.state.inspect = None
#         request.state.user = None
#         request.state.is_admin_access = None
#         ip_from = request.headers["x-forwarded-for"] if "x-forwarded-for" in request.headers.keys() else None
#
#         if await self.url_pattern_check(request.url.path,
#                                         self.except_path_regex) or request.url.path in self.except_path_list:
#             return await self.app(scope, receive, send)
#         try:
#             if request.url.path.startswith("/api"):
#                 # api 인경우 헤더로 토큰 검사
#                 if "authorization" in request.headers.keys():
#                     token_info = await self.token_decode(access_token=request.headers.get("Authorization"))
#                     request.state.user = UserToken(**token_info)
#                     # 토큰 없음
#                 else:
#                     if "Authorization" not in request.headers.keys():
#                         raise ex.NotAuthorized()
#             else:
#                 # 템플릿 렌더링인 경우 쿠키에서 토큰 검사
#                 # request.cookies["Authorization"] = "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MTQsImVtYWlsIjoia29hbGFAZGluZ3JyLmNvbSIsIm5hbWUiOm51bGwsInBob25lX251bWJlciI6bnVsbCwicHJvZmlsZV9pbWciOm51bGwsInNuc190eXBlIjpudWxsfQ.4vgrFvxgH8odoXMvV70BBqyqXOFa2NDQtzYkGywhV48"
#
#                 if "Authorization" not in request.cookies.keys():
#                     raise ex.NotAuthorized()
#
#                 token_info = await self.token_decode(access_token=request.cookies.get("Authorization"))
#                 request.state.user = UserToken(**token_info)
#
#             request.state.req_time = D.datetime()
#             print(D.datetime())
#             print(D.date())
#             print(D.date_num())
#
#             print(request.cookies)
#             print(headers)
#             res = await self.app(scope, receive, send)
#         except APIException as e:
#             res = await self.exception_handler(e)
#             res = await res(scope, receive, send)
#         finally:
#             # Logging
#             ...
#         return res
#
#     @staticmethod
#     async def url_pattern_check(path, pattern):
#         result = re.match(pattern, path)
#         if result:
#             return True
#         return False
#
#     @staticmethod
#     async def token_decode(access_token):
#         """
#         :param access_token:
#         :return:
#         """
#         try:
#             access_token = access_token.replace("Bearer ", "")
#             payload = jwt.decode(access_token, key=consts.JWT_SECRET, algorithms=[consts.JWT_ALGORITHM])
#         except ExpiredSignatureError:
#             raise ex.TokenExpiredEx()
#         except DecodeError:
#             raise ex.TokenDecodeEx()
#         return payload
#
#     @staticmethod
#     async def exception_handler(error: APIException):
#         error_dict = dict(status=error.status_code, msg=error.msg, detail=error.detail, code=error.code)
#         res = JSONResponse(status_code=error.status_code, content=error_dict)
#         return res


async def url_pattern_check(path, pattern):
    result = re.match(pattern, path)
    if result:
        return True
    return False


async def token_decode(access_token):
    """
    :param access_token:
    :return:
    """
    try:
        access_token = access_token.replace("Bearer ", "")
        payload = jwt.decode(access_token, key=consts.JWT_SECRET, algorithms=[consts.JWT_ALGORITHM])
    except ExpiredSignatureError:
        raise ex.TokenExpiredEx()
    except DecodeError:
        raise ex.TokenDecodeEx()
    return payload


async def exception_handler(error: Exception):
    if not isinstance(error, APIException):
        error = APIException(ex=error, detail=str(error))

    return error
