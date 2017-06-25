# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import os,time,datetime
import json,urllib
#import paramiko
from django.core.paginator import Paginator
from django.core.paginator import EmptyPage
from django.shortcuts import render,render_to_response
from django.http import HttpResponseRedirect,HttpResponse
from models import UserName,UserGroup,Assest,AssestGroup
from django.core.paginator import PageNotAnInteger
from django.views.decorators.csrf import csrf_exempt
from api import *
from django import forms
from django.contrib.auth.hashers import *
from django.http import StreamingHttpResponse
# Create your views here.

class UserForm(forms.Form):
    username = forms.CharField(label='用户名', max_length=100)
    password = forms.CharField(label='密码', widget=forms.PasswordInput())

@require_role('SU')
def group_list(request):
    limit = 10  # 每页显示的记录数
    group_all = UserGroup.objects.all()
    user_all = UserName.objects.all()
    paginator = Paginator(group_all, limit)  # 实例化一个分页对象
    page = request.GET.get('page')  # 获取页码
    try:
        group_all = paginator.page(page)  # 获取某页对应的记录
    except PageNotAnInteger:  # 如果页码不是个整数
        group_all = paginator.page(1)  # 取第一页的记录
    except EmptyPage:  # 如果页码太大，没有相应的记录
        group_all = paginator.page(paginator.num_pages)  # 取最后一页的记录
    return render(request, 'group/group_list.html', {'group_all':group_all, 'data':group_all})

@csrf_exempt
@require_role('SU')
def group_add(request):
    error = ''
    user_all = UserName.objects.all()
    if request.method == 'POST':
        groupname = request.POST.get('groupname')
        print groupname,type(groupname)
        name = request.POST.get('name')
        comment = request.POST.get('comment')
        #获取前端复选返回的users列表
        users = request.POST.getlist('qsl', '')
        users_str = ','.join(users)
        try:
            # 对用户组为空、用户组已存在的异常进行处理
            if UserGroup.objects.filter(groupname=groupname):
                error = u'%s already exits.' % groupname
                #return render(request, 'group/group_add.html', {'error':error})
                raise ServerError(error)
            if not groupname:
                error = u'用户组groupname不能为空'
                raise ServerError(error)
            group = UserGroup()
            group.groupname = groupname
            group.name = name
            group.comment = comment
            group.save()
            groupid = UserGroup.objects.get(groupname=groupname)
            if len(users_str) > 0:
                user_list = ','.join(users).split(',')
                for user in user_list:
                    user_obj = UserName.objects.get(username=user)
                    user_obj.group.add(groupid)
                return HttpResponseRedirect('/auser/group/list/')
            return HttpResponseRedirect('/auser/group/list/')
        except ServerError:
            pass
        except TypeError:
            error = u'添加用户组失败'
        #group = UserGroup()
        #group.groupname = groupname
        #group.name = name
        #group.comment = comment
        #group.save()
        #groupid = UserGroup.objects.get(groupname=groupname)
        #if len(users_str) > 0:
        #    user_list = ','.join(users).split(',')
        #    for user in user_list:
        #        user_obj = UserName.objects.get(username=user)
        #        user_obj.group.add(groupid)
        #    return HttpResponseRedirect('/auser/group/list/')
        #return HttpResponseRedirect('/auser/group/list/')
    return render(request,'group/group_add.html', {'error':error,'user_all':user_all})

@require_role('SU')
def group_del(request):
    if request.method == 'GET':
        group_id = request.GET.get('id')
        UserGroup.objects.filter(id=group_id).delete()
        return HttpResponseRedirect('/auser/group/list/')

@require_role('SU')
def group_update(request):
    group_id = request.GET.get('id')
    user_all = UserName.objects.all()
    if group_id:
        data = UserGroup.objects.get(id=group_id)
        return render(request, 'group/group_update.html', {'data': data,'user_all':user_all})
    data = ''
    if request.method == 'POST':
        group_id = request.POST.get('id')
        groupname = request.POST.get('groupname')
        name = request.POST.get('name')
        comment = request.POST.get('comment')
        users = request.POST.getlist('qsl', '')
        groupid = UserGroup.objects.get(id=group_id)
        if users:
            user_list = ','.join(users).split(',')
            for user in user_list:
                user_obj = UserName.objects.get(username=user)
                user_obj.group.update(groupid)
        UserGroup.objects.filter(id=group_id).update(groupname=groupname,name=name,comment=comment)
        return HttpResponseRedirect('/auser/group/list/')
    return render(request, 'group/group_update.html', {'data': data,'user_all':user_all})

#删除所选数据
@require_role('SU')
def delSelect(request):
     arr = request.GET['arr']
     print arr
     blist="("+arr+")" # 根据列表构建元组
     UserGroup.objects.extra(where=['id IN '+str(blist)+'']).delete()
     return HttpResponse("delect success")

#删除所选数据
@require_role('SU')
def deluserSelect(request):
     arr = request.GET['arr']
     print arr
     blist="("+arr+")" # 根据列表构建元组
     UserName.objects.extra(where=['id IN '+str(blist)+'']).delete()
     return HttpResponse("delect success")

#删除所选数据

def delassestgroupSelect(request):
     arr = request.GET['arr']
     print arr
     blist="("+arr+")" # 根据列表构建元组
     AssestGroup.objects.extra(where=['id IN '+str(blist)+'']).delete()
     return HttpResponse("delect success")

#删除所选数据
def delsysuserSelect(request):
    arr = request.GET['arr']
    blist = "(" + arr + ")"  # 根据列表构建元组
    SysUser.objects.extra(where=['id IN ' + str(blist) + '']).delete()
    return HttpResponse("delect success")

#显示一条数据

def queryByAssestgroup(request):
   # id=request.GET['id'];
    hostgroupname=request.GET['hostgroupname']
    print hostgroupname
    if hostgroupname == "": #若无输入，则转移到query查询所有
        return HttpResponseRedirect("/auser/assestgroup/list/")
    assestgroup_all=AssestGroup.objects.filter(hostgroupname=hostgroupname) #通过id 过滤结果，是一字典类型
    return render(request,'assestgroup/assestgroup_list.html',{'assestgroup_all':assestgroup_all})


#显示一条数据
@require_role('CU')
def queryById(request):
   # id=request.GET['id'];
    name=request.GET['name']
    print name
    if name == "": #若无输入，则转移到query查询所有
       return HttpResponseRedirect("/auser/group/list/")
    group_all=UserGroup.objects.filter(name=name) #通过id 过滤结果，是一字典类型
    return render(request,'group/group_list.html',{'group_all':group_all})

#显示一条数据

def queryBysysuser(request):
   # id=request.GET['id'];
    username=request.GET['username']
    print username
    if username == "": #若无输入，则转移到query查询所有
       return HttpResponseRedirect("/auser/sysuser/list/")
    sysuser_all=SysUser.objects.filter(username=username) #通过id 过滤结果，是一字典类型
    return render(request,'sysuser/sysuser_list.html',{'sysuser_all': sysuser_all})

#显示一条数据
@require_role('CU')
def queryByuser(request):
   # id=request.GET['id'];
    name=request.GET['name']
    print name
    if name == "": #若无输入，则转移到query查询所有
       return HttpResponseRedirect("/auser/user/list/")
    user_all=UserName.objects.filter(name=name) #通过id 过滤结果，是一字典类型
    return render(request,'user/user_list.html',{'user_all':user_all})

@require_role('CU')
def user_list(request):
    limit = 10  # 每页显示的记录数
    user_all = UserName.objects.all()
    paginator = Paginator(user_all, limit)  # 实例化一个分页对象
    page = request.GET.get('page')  # 获取页码
    try:
        user_all = paginator.page(page)  # 获取某页对应的记录
    except PageNotAnInteger:  # 如果页码不是个整数
        user_all = paginator.page(1)  # 取第一页的记录
    except EmptyPage:  # 如果页码太大，没有相应的记录
        user_all = paginator.page(paginator.num_pages)  # 取最后一页的记录
    return render(request, 'user/user_list.html', {'user_all': user_all, 'data': user_all})

#@require_role('SU')
def user_add(request):
    error = ''
    group_all = UserGroup.objects.all()
    if request.method == 'POST':
        name = request.POST.get('name')
        role = request.POST.get('role')
        groups = request.POST.getlist('qsl', '')
        groups_str = ','.join(groups)
        print groups_str
        uf = UserForm(request.POST)
        if uf.is_valid():
            username = uf.cleaned_data['username']
            password = uf.cleaned_data['password']
            try:
                if UserName.objects.filter(username=username):
                    error = u'%s already exits.' % username
                    #return render(request, 'group/group_add.html', {'error': error})
                    raise ServerError(error)
                if not username:
                    error = u'用户username不能为空'
                    raise ServerError(error)
                user = UserName()
                user.username = username
                user.name = name
                user.role = role
                user.passwd = password
                user.save()
                userid = UserName.objects.get(username=username)
                if len(groups_str) > 0:
                    group_list = ','.join(groups).split(',')
                    for group in group_list:
                        group_obj = UserGroup.objects.get(groupname=group)
                        userid.group.add(group_obj)
                return HttpResponseRedirect('/auser/user/list/')
            except ServerError:
                pass
            except TypeError:
                error = u'添加用户失败'
    return render(request, 'user/user_add.html', {'error': error, 'group_all':group_all})

@require_role('SU')
def user_update(request):
    user_id = request.GET.get('id')
    group_all = UserGroup.objects.all()
    if user_id:
        data = UserName.objects.get(id=user_id)
        return render(request, 'user/user_update.html', {'data': data, 'group_all': group_all})
    if request.method == 'POST':
        user_id = request.POST.get('id')
        username = request.POST.get('username')
        name = request.POST.get('name')
        role = request.POST.get('role')
        groups = request.POST.getlist('qsl', '')
        user_obj = UserName.objects.get(id=user_id)
        if groups:
            group_list = ','.join(groups).split(',')
            for group in group_list:
                group_obj = UserGroup.objects.get(groupname=group)
                user_obj.group.update(group_obj)
        UserName.objects.filter(id=user_id).update(username=username,name=name,role=role)
        return HttpResponseRedirect('/auser/user/list/')
    return render(request, 'user/user_update.html', {'user_all': group_all})

@require_role('SU')
def user_del(request):
    if request.method == 'GET':
        user_id = request.GET.get('id')
        UserName.objects.filter(id=user_id).delete()
        return HttpResponseRedirect('/auser/user/list/')

def user_am(request):
    return render(request, 'group/1.html')

def sys_info(request):
    return render(request, 'navigat.html')

def login(request):
    if request.method == 'POST':
        uf = UserForm(request.POST)
        if uf.is_valid():
            # 获取表单用户密码
            username = uf.cleaned_data['username']
            password = uf.cleaned_data['password']
            # 将原密码进行加密与数据库中密码作比较
            password = make_password(password, 'a', 'pbkdf2_sha256')
            # 获取的表单数据与数据库进行比较
            user = UserName.objects.filter(username=username, passwd=password)
            if user:
                # 比较成功，跳转index
                response = HttpResponseRedirect('/auser/index/')
                # 将username写入浏览器cookie,失效时间为3600
                response.set_cookie('username', username, 3600)
                return response
            else:
                # 比较失败，还在login
                error = u'用户名或密码错误'
                return render(request, 'user/login.html', {'error':error})
    else:
        uf = UserForm()
    return render_to_response('user/login.html', {'uf': uf})

def assestgroup_list(request):
    limit = 10  # 每页显示的记录数
    assestgroup_all = AssestGroup.objects.all()
    paginator = Paginator(assestgroup_all, limit)  # 实例化一个分页对象
    page = request.GET.get('page')  # 获取页码
    try:
        assestgroup_all = paginator.page(page)  # 获取某页对应的记录
    except PageNotAnInteger:  # 如果页码不是个整数
        assestgroup_all = paginator.page(1)  # 取第一页的记录
    except EmptyPage:  # 如果页码太大，没有相应的记录
        assestgroup_all = paginator.page(paginator.num_pages)  # 取最后一页的记录
    return render(request, 'assestgroup/assestgroup_list.html', {'assestgroup_all': assestgroup_all, 'data': assestgroup_all})

def assestgroup_add(request):
    error = ''
    assest_all = Assest.objects.all()
    if request.method == 'POST':
        hostgroupname = request.POST.get('hostgroupname')
        #hosts = request.POST.getlist('qsl', '')
        comment = request.POST.get('comment')
        try:
            if AssestGroup.objects.filter(hostgroupname=hostgroupname):
                error = u'%s 资产组名已经存在' % hostgroupname
                raise ServerError(error)
            if not hostgroupname:
                error = u'资产组名不能为空'
                raise ServerError(error)
            assestgroup = AssestGroup()
            assestgroup.hostgroupname = hostgroupname
            assestgroup.comment = comment
            assestgroup.save()
            return HttpResponseRedirect('/auser/assestgroup/list/')
        except ServerError:
            pass
        except TypeError:
            error = u'添加资产组失败'
    return render(request, 'assestgroup/assestgroup_add.html', {'error': error, 'assest_all':assest_all})

def assestgroup_del(request):
    if request.method == 'GET':
        assestgroup_id = request.GET.get('id')
        AssestGroup.objects.filter(id=assestgroup_id).delete()
        return HttpResponseRedirect('/auser/assestgroup/list/')

def assestgroup_update(request):
    if request.method == 'GET':
        assestgroup_id = request.GET.get('id')
        data = AssestGroup.objects.get(id=assestgroup_id)
        return render(request, 'assestgroup/assestgroup_update.html', {'data':data})
    if request.method == 'POST':
        assestgroup_id = request.POST.get('id')
        hostgroupname = request.POST.get('hostgroupname')
        comment = request.POST.get('comment')
        AssestGroup.objects.filter(id=assestgroup_id).update(hostgroupname=hostgroupname, comment=comment)
        hosts = request.POST.getlist('qsl', '')
        assestgroupid = AssestGroup.objects.get(id=assestgroup_id)
        host_str = ','.join(hosts)
        if len(host_str) > 0:
            host_list = host_str.split(',')
            for host in host_list:
                host_obj = Assest.objects.get(hostname=host)
                host_obj.assestgroup.update(assestgroupid)
                assestgroup_all = AssestGroup.objects.all()
                return render(request, 'assestgroup/assestgroup_list.html', {'assestgroup_all':assestgroup_all})
        assestgroup_all = AssestGroup.objects.all()
        return render(request, 'assestgroup/assestgroup_list.html', {'assestgroup_all':assestgroup_all})

def assest_list(request):
    limit = 10
    assest_all = Assest.objects.all()
    paginator = Paginator(assest_all, limit)  # 实例化一个分页对象
    page = request.GET.get('page')  # 获取页码
    try:
        assest_all = paginator.page(page)  # 获取某页对应的记录
    except PageNotAnInteger:  # 如果页码不是个整数
        assest_all = paginator.page(1)  # 取第一页的记录
    except EmptyPage:  # 如果页码太大，没有相应的记录
        assest_all = paginator.page(paginator.num_pages)  # 取最后一页的记录
    return render(request, 'assestgroup/assest_list.html',{'assest_all': assest_all, 'data': assest_all})

def assest_add(request):
    error = ''
    assestgroup_all = AssestGroup.objects.all()
    if request.method == 'POST':
        hostname = request.POST.get('hostname')
        ip = request.POST.get('ipaddr')
        password = request.POST.get('password')
        port = request.POST.get('port')
        idc = request.POST.get('idc')
        OS = request.POST.get('OS')
        cpu_num = request.POST.get('cpu_num')
        mem_info = request.POST.get('mem_info')
        hostgroups = request.POST.getlist('qsl', '')
        hdd_type = request.POST.get('hdd_type')
        print hdd_type
        hdd_num = request.POST.get('hdd_num')
        comment = request.POST.get('comment')
        try:
            if Assest.objects.filter(ipaddr=ip):
                error = u'%s 该主机已经存在' % ip
                raise ServerError(error)
            if not ip:
                error = u'ip地址不能为空'
                raise ServerError(error)
            assest = Assest()
            assest.hostname = hostname
            assest.ipaddr = ip
            assest.passwd_key = password
            assest.port = port
            assest.IDC = idc
            assest.OS = OS
            assest.cpu_num = cpu_num
            assest.mem_info = mem_info
            assest.hdd_type = hdd_type
            assest.hdd_num = hdd_num
            assest.comment = comment
            assest.save()
            hostgroup_str = ','.join(hostgroups)
            assestid = Assest.objects.get(hostname=hostname)
            if len(hostgroup_str) > 0:
                hostgroup_list = hostgroup_str.split(',')
                for hostgroup in hostgroup_list:
                    hostgroupid = AssestGroup.objects.get(hostgroupname=hostgroup)
                    assestid.assestgroup.add(hostgroupid)
            return HttpResponseRedirect('/auser/assest/list/')
        except ServerError:
            pass
        except TypeError:
            error = u'添加主机失败'
    return render(request, 'assestgroup/assest_add.html', {'error':error, 'assestgroup_all':assestgroup_all})

def assest_del(request):
    if request.method == 'GET':
        assest_id = request.GET.get('id')
        Assest.objects.filter(id=assest_id).delete()
        return HttpResponseRedirect('/auser/assest/list/')

def assest_update(request):
    if request.method == 'GET':
        assest_id = request.GET.get('id')
        assest_all = Assest.objects.get(id=assest_id)
        assestgroup_all = AssestGroup.objects.all()
        assestid = Assest.objects.get(id=assest_id)
        assestgroup_obj = assestid.assestgroup.all()
        return render(request, 'assestgroup/assest_update.html', {'data': assest_all, 'assestgroup_all':assestgroup_all, 'assestgroup_obj': assestgroup_obj})
    if request.method == 'POST':
        assest_id = request.POST.get('id')
        hostname = request.POST.get('hostname')
        ip = request.POST.get('ipaddr')
        password = request.POST.get('password')
        port = request.POST.get('port')
        idc = request.POST.get('idc')
        OS = request.POST.get('OS')
        cpu_num = request.POST.get('cpu_num')
        mem_info = request.POST.get('mem_info')
        hostgroups = request.POST.getlist('qsl', '')
        hdd_type = request.POST.get('hdd_type')
        hdd_num = request.POST.get('hdd_num')
        comment = request.POST.get('comment')
        Assest.objects.filter(id=assest_id).update(hostname=hostname, comment=comment, ipaddr=ip, passwd_key=password, port=port, IDC=idc, OS=OS, cpu_num=cpu_num, mem_info=mem_info, hdd_num=hdd_num, hdd_type=hdd_type)
        hostgroup_str = ','.join(hostgroups)
        if len(hostgroup_str) > 0:
            hostgroup_list = hostgroup_str.split(',')
            for hostgroup in hostgroup_list:
                hostgroupid = AssestGroup.objects.get(hostgroupname=hostgroup)
                #assestgroupid = AssestGroup.objects.all()
                #assestid.assestgroup.filter(hostgroupname=hostgroup).delete()
                assestid.assestgroup.add(hostgroupid)
        return HttpResponseRedirect('/auser/assest/list/')

def sysuser_list(request):
    limit = 10  # 每页显示的记录数
    sysuser_all = SysUser.objects.all()
    paginator = Paginator(sysuser_all, limit)  # 实例化一个分页对象
    page = request.GET.get('page')  # 获取页码
    try:
        sysuser_all = paginator.page(page)  # 获取某页对应的记录
    except PageNotAnInteger:  # 如果页码不是个整数
        sysuser_all = paginator.page(1)  # 取第一页的记录
    except EmptyPage:  # 如果页码太大，没有相应的记录
        sysuser_all = paginator.page(paginator.num_pages)  # 取最后一页的记录
    return render(request, 'sysuser/sysuser_list.html', {'sysuser_all': sysuser_all, 'data': sysuser_all})

def sysuser_add(request):
    error = ''
    if request.method == 'POST':
        username = request.POST.get('username')
        user = request.POST.get('user')
        print user
        usergroup = request.POST.get('usergroup')
        assest = request.POST.get('assest')
        assestgroup = request.POST.get('assestgroup')
        comment = request.POST.get('comment')
        try:
            if SysUser.objects.filter(username=username):
                error = u'%s 该系统用户已存在' % username
                raise ServerError(error)
            if not username:
                error = u'username不能为空'
                raise ServerError(error)
            SysUser.objects.get_or_create(username=username, comment=comment)
            sysuserid = SysUser.objects.get(username=username)
            if user:
                userid = UserName.objects.get(username=user)
                sysuserid.user.add(userid)
            if usergroup:
                usergroupid = UserGroup.objects.get(groupname=usergroup)
                sysuserid.usergroup.add(usergroupid)
            if assest:
                assestid = Assest.objects.get(hostname=assest)
                sysuserid.assest.add(assestid)
            if assestgroup:
                assestgroupid = AssestGroup.objects.get(hostgroupname=assestgroup)
                sysuserid.assestgroup.add(assestgroupid)
            return HttpResponseRedirect('/auser/sysuser/list/')
        except ServerError:
            pass
        except TypeError:
            error = u'添加系统用户失败'
    return render(request, 'sysuser/sysuser_add.html', {'error': error})

def sysuser_del(request):
    if request.method == 'GET':
        sysuser_id = request.GET.get('id')
        SysUser.objects.filter(id=sysuser_id).delete()
        return HttpResponseRedirect('/auser/sysuser/list/')

def sysuser_update(request):
    if request.method == 'GET':
        sysuser_id = request.GET.get('id')
        sysuser_all = SysUser.objects.get(id=sysuser_id)
        return render(request, 'sysuser/sysuser_update.html', {'sysuser_all': sysuser_all})
    if request.method == 'POST':
        sysuser_id = request.POST.get('id')
        username = request.POST.get('username')
        user = request.POST.get('user')
        usergroup = request.POST.get('usergroup')
        assest = request.POST.get('assest')
        assestgroup = request.POST.get('assestgroup')
        comment = request.POST.get('comment')
        sysuserid = SysUser.objects.get(id=sysuser_id)
        SysUser.objects.filter(id=sysuser_id).update(username=username, comment=comment)
        if UserName.objects.get(username=user):
            userid = UserName.objects.get(username=user)
            sysuserid.user.add(userid)
        if UserGroup.objects.get(groupname=usergroup):
            usergroupid = UserGroup.objects.get(groupname=usergroup)
            sysuserid.usergroup.add(usergroupid)
        if Assest.objects.get(hostname=assest):
            assestid = Assest.objects.get(hostname=assest)
            sysuserid.assest.add(assestid)
        if AssestGroup.objects.get(hostgroupname=assestgroup):
            assestgroupid = AssestGroup.objects.get(hostgroupname=assestgroup)
            sysuserid.assestgroup.add(assestgroupid)
        return HttpResponseRedirect('/auser/sysuser/list/')

# def push(request):
#     if request.method == 'GET':
#         sysuser_id = request.GET.get('id')
#         print sysuser_id
#         sysuserid = SysUser.objects.get(id=sysuser_id)
#         sysuser = sysuserid.username
#         for hostinfo in sysuserid.assest.all():
#             ip = hostinfo.ipaddr
#             username = hostinfo.hostname
#             password = hostinfo.passwd_key
#             port = hostinfo.port
#         print ip,username,password
#         #指定系统用户登录的shell，选择要连接的主机
#         os.system("useradd -s /opt/assestmanage/init.sh %s" % sysuser)
#         os.system("echo -e  '\n'|ssh-keygen -t rsa -P '' ")
#         os.system("cp /root/.ssh/id_rsa.pub /root/.ssh/authorized_keys")
#         os.system("cd /root/.ssh/;chmod 600 authorized_keys")
#         home_dir = os.path.join('/home/', sysuser, '.ssh')
#         #if not os.path.exists(home_dir):
#         #    os.mkdir(home_dir)
#         '''
#         连接客户端创建系统用户、.ssh目录、创建authorized_keys文件
#         '''
#         ssh = paramiko.SSHClient()
#         ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#         ssh.connect(ip, port, username, password)
#         stdin, stdout, stderr = ssh.exec_command("useradd %s" % sysuser)
#         stdin, stdout, stderr = ssh.exec_command("cp -a /etc/skel/. /home/%s/" % sysuser)
#         stdin, stdout, stderr = ssh.exec_command("mkdir -p %s" % home_dir)
#         stdin, stdout, stderr = ssh.exec_command("touch %s/authorized_keys" % home_dir)
#         ssh.close()
#         '''
#         推送authorized_keys文件到客户端
#         '''
#         t = paramiko.Transport((ip, port))
#         t.connect(username=username, password=password)
#         sftp = paramiko.SFTPClient.from_transport(t)
#         remotepath = os.path.join(home_dir, 'authorized_keys')
#         # remotepath='/usr/local/src/'
#         localpath = '/root/.ssh/authorized_keys'
#         sftp.put(localpath, remotepath)
#         os.system("chown -R %s.%s /home/%s/" % (sysuser, sysuser, sysuser))
#         t.close()
#         '''
#         连接客户端修改authorized_keys文件的权限
#         '''
#         ssh = paramiko.SSHClient()
#         ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#         ssh.connect(ip, port, username, password)
#         stdin, stdout, stderr = ssh.exec_command("chown -R %s.%s %s" % (sysuser, sysuser, home_dir))
#         stdin, stdout, stderr = ssh.exec_command("cd %s;chmod 600 authorized_keys" % (home_dir))
#         ssh.close()
#         msg = u'推送成功'
#         return render(request, 'sysuser/sysuser_list.html', {'msg': msg})

def ansible_config(request):
    assestgroup_all = AssestGroup.objects.all()
    assestgroup_dic = {}
    for assestgroup in assestgroup_all:
        hostgroupname_name = assestgroup.hostgroupname
        print hostgroupname_name
        assestgroup_dic[hostgroupname_name] = []
        print assestgroup_dic
        assestgroupid = AssestGroup.objects.get(hostgroupname=hostgroupname_name)
        hosts = assestgroupid.assest_set.all()
        for host in hosts:
            host_ip = host.ipaddr
            assestgroup_dic[hostgroupname_name].append(host_ip)
    data = json.dumps(assestgroup_dic,encoding='UTF-8', ensure_ascii=False)
    data_dic = json.loads(data)
    print data_dic
    ansible_config = \
    '''
    [%s]
    %s
    '''
    ansible_conf = '/etc/ansible/hosts'
    a_list = []
    for k in data_dic:
        v_list = data_dic[k]
        v = '\n'.join(v_list)
        a = ansible_config % (k,v)
        a_list.append(a)
    a_str = ''.join(a_list)
    with open(ansible_conf, 'w') as f:
        f.write(a_str)
    #返回用于测试的api
    return HttpResponse(data)

def index(request):
    def week_get(vdate):
        dayscount = datetime.timedelta(days=vdate.isoweekday())
        dayfrom = vdate - dayscount + datetime.timedelta(days=1)
        dayto = vdate - dayscount + datetime.timedelta(days=7)
        # print ' ~~ '.join([str(dayfrom), str(dayto)])
        week7 = []
        i = 0
        while (i <= 6):
            week7.append(str(dayfrom + datetime.timedelta(days=i)))
            i += 1
        return week7
    vdate_str = time.strftime('%Y-%m-%d',time.localtime(time.time()))
    vdate = datetime.datetime.strptime(vdate_str, '%Y-%m-%d').date()
    week_date = json.dumps(week_get(vdate))
    data_gg = json.dumps([
                {'value':'3', 'name':'直接访问'},
                {'value':'5', 'name':'邮件营销'},
                {'value':'4', 'name':'联盟广告'},
                {'value':'5', 'name':'视频广告'},
                {'value':'8', 'name':'搜索引擎'}
    ])
    data = json.dumps([9,17,26,10,5,4,15])
    return render(request, 'index.html', {'date': week_date, 'data': data, 'data_gg':data_gg })

def upload(request):
    if request.method == "POST":
        dir_path = os.path.dirname(os.path.abspath(__file__))
        print dir_path
        #data = request.POST.get('data')
        #data = request.body
        #print request.body

        #print request.readlines()

        #file = len(request.readlines())
        #print request.readlines()
        for file in request.FILES:
            print file
            print type(file)
            data = request.FILES.get(file)
            print type(data)
            #print data.read()
            file_path = os.path.join(dir_path,file)
            print file_path
            with open(file_path, 'w') as f:
                f.write(data.read())
        #print dir(request.FILES)
        return HttpResponse('Succed!')
    #        #获取表单信息
    #        headImg = uf.cleaned_data['headImg']
    #        #写入数据库
    #        user = Upload()
    #        user.headImg = headImg
    #        user.save()
    #        return HttpResponse('upload ok!')
    return render_to_response('upload.html')

def download(request):
    if request.method == 'GET':
        file_name = request.GET.get('filename')
        file_path = os.path.join(os.path.dirname(__file__),file_name)
        def file_iterator(file_path, chunk_size=512):
            with open(file_path) as f:
                while True:
                    c = f.read(chunk_size)
                    if c:
                        yield c
                    else:
                        break

        file_iterator(file_path, chunk_size=512)
        the_file_name = file_name
        response = StreamingHttpResponse(file_iterator(the_file_name))
        response['Content-Type'] = 'application/octet-stream'
        response['Content-Disposition'] = 'attachment;filename="{0}"'.format(the_file_name)

    return response