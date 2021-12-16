from fastapi import APIRouter
from starlette.requests import Request
from database.schema import Users
from models import UserMe


router = APIRouter()


@router.get("/me", response_model=UserMe)
async def get_me(request: Request):
    """
    get my info
    :param request:
    :return:
    """
    user = request.state.user
    #     # user_info = Users.get(id=user.id)
    user_info = Users.filter(id__gt=user.id).order_by("email").count()
    # user_info = session.query(Users).filter(Users.id > user.id).order_by(Users.email.asc()).count()
    return user_info


@router.put('/me')
async def put_me(request: Request):
    ...


