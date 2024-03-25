from django.test import TestCase

from users import services
from users.models import User


class TestServices(TestCase):
    """
    Test case for user services.
    """
    def test_user_create_service(self):
        self.assertEqual(0, User.objects.count())
        user = services.user_create(email='test@example.com',
                                    username='test',
                                    password='testpass123')
        self.assertEqual(1, User.objects.count())
        self.assertEqual(user, User.objects.first())
