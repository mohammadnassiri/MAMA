from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('download', views.download, name='download'),
    path('result', views.result, name='result'),
    path('collect/<type>', views.collect, name='collect'),
]