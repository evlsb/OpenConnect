from django.urls import path

from .views import CACreate, ServerCreate, ClientCreate

urlpatterns = [
    path('cacreate/', CACreate),
    path('servercreate/', ServerCreate),
    path('clientcreate/', ClientCreate),
]