from rest_framework import serializers

from users.models import User


class UserIn(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('email', 'username', 'password',)


class UserOut(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('email', 'username', 'avatar_url',)
