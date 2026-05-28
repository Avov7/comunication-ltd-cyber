from django.urls import path
from . import views

urlpatterns = [
    path('add', views.add_client, name='add_client'),
    path('<int:client_id>/', views.client_detail, name='client_detail'),
]
