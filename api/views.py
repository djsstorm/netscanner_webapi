from django.shortcuts import render
from django.http import HttpResponse
from api.api_functions import API

api = API()

def poweron(request):

    res = api.power_on()
    return HttpResponse(res)



def poweroff(request):
    res = api.power_off()
    return HttpResponse(res)

def systemhealth(request):
    res = api.get_system_health()
    #return render(request, 'api/system_health.html', res)
    return HttpResponse(res)


def logger(request):
    res = api.get_logger()
    #return render(request, 'api/logger.html', res)
    return HttpResponse(res)


def systemstatus(request):
    res = api.get_system_status()
    return HttpResponse(res)

def hosts(request):

    #res = MyClass.the_static_method()
    res = api.get_hosts()
    #return render(request, 'api/hosts.html', res)
    return HttpResponse(res)


def securitybreaches(request):
    res = api.get_security_breaches()
    return HttpResponse(res)

