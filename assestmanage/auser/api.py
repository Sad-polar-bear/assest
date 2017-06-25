#coding:utf-8

from auser.models import *
from django.http import HttpResponse
from django.shortcuts import render

class ServerError(Exception):
    '''
    自定义异常
    '''
    pass

def require_role(role="user"):
    def _deco(func):
        def __deco(request, *args, **kwargs):
            if request.COOKIES.has_key('username'):
                username = request.COOKIES['username']
                print username
                username_obj = UserName.objects.get(username=username)
                user_role =  username_obj.role
                print user_role
                if user_role == role or user_role == 'SU':
                    return func(request, *args, **kwargs)
                error = "ATTENTION:  %s has no permition" % username
                #return HttpResponse("ERROR: %s has no permition" % username)
                return render(request, 'user/login.html', {'error':error})
            error = 'SORRY: You have no permition login'
            #return HttpResponse("SORRY: You have no permition login")
            return render(request, 'user/login.html', {'error':error})
        return __deco
    return _deco