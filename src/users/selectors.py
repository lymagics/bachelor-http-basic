from users.models import User


def user_get(username: str) -> User:
    return (
        User
        .objects
        .filter(username=username)
        .first()
    )
