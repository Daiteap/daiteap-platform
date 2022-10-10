from django.conf.urls import include, url
from django.urls import path

urlpatterns = [
    url('', include("django_prometheus.urls")),
    path('', include('cloudcluster.v1_0_0.urls')),
]
