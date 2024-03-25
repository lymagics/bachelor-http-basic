from django.test import TestCase

from users import selectors
from users.tests.factories import UserFactory


class TestSelectors(TestCase):
    """
    Test case for user selectors.
    """
    def test_user_get(self):
        new_user = UserFactory()
        user = selectors.user_get(username=new_user.username)
        self.assertIsNotNone(user)
        self.assertEqual(user, new_user)
