from django.conf.urls import include, url
from django.contrib import admin
from api import views
from api.models import Category

urlpatterns = [

    url(r'^admin/', include(admin.site.urls)),
    url(r'^api/', include('api.urls')),


]
