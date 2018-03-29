from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('request', views.request, name='request'),
    path('download', views.download, name='download'),
    path('result', views.result, name='result'),
    path('check', views.check, name='check'),
    path('collect', views.collect, name='collect'),  # collect dataset. type = benign or malware
    path('vbox', views.vbox, name='vbox'),  # create vboxes. name = name of the vbox
    path('restore', views.restore, name='restore'),  # restore single vbox. name = name of the vbox
    path('option/<param>', views.option, name='option'),  # pause, resume, poweroff
]