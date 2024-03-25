from django.urls import path

from users.api import views

urlpatterns = [
    path('create/', views.user_create, name='create'),
    path('me/', views.user_get, name='me'),
]

app_name = 'users'
