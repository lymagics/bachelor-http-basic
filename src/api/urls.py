from django.urls import include, path

urlpatterns = [
    path('users/', include('users.urls')),
]

app_name = 'api'
