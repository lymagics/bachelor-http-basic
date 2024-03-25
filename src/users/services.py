from users.models import User


def user_create(
    email: str,
    username: str,
    password: str
) -> User:
    user = User(email=email, username=username)
    user.set_password(password)
    user.full_clean()
    user.save()
    return user
