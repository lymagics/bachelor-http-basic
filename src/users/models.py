from hashlib import md5

from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """
    User entity.
    """
    email = models.EmailField(unique=True)

    @property
    def avatar_url(self) -> str:
        avatar_hash = md5(self.email.encode()).hexdigest()
        return f'https://www.gravatar.com/avatar/{avatar_hash}?d=mp'
