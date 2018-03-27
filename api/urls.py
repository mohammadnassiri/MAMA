from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('request', views.request, name='request'),
    path('download', views.download, name='download'),
    path('result', views.result, name='result'),
    path('check', views.check, name='check'),
    path('collect/<type>', views.collect, name='collect'),  # collect dataset. type = benign or malware
    path('vbox/<name>', views.vbox, name='vbox'),  # create vboxes. name = name of the vbox
    path('pause/<status>', views.pause, name='pause'),  # status = pause all agents, status = resume all agents
]