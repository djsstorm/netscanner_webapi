from django.conf.urls import patterns, url
from api import views


urlpatterns = patterns('',

                url('poweron/', views.poweron, name='poweron'),
                url('poweroff/', views.poweroff, name='poweroff'),
                url('systemhealth/', views.systemhealth, name='systemhealth'),
                url('logger/', views.logger, name='logger'),
                url('systemstatus/', views.systemstatus, name='getsystemstatus'),
                url('hosts/', views.hosts, name='hosts'),
                url('securitybreaches/', views.securitybreaches, name='securitybreachs'),
                )
