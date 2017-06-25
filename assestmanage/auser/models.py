# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib.auth.hashers import *
from django.db import models

# Create your models here.

class UserGroup(models.Model):
    groupname = models.CharField(max_length=80)
    name = models.CharField(max_length=200, blank=True, null=True)    #支持中文名字，可以为空
    comment = models.CharField(max_length=200)

    def __unicode__(self):
        return self.groupname

class UserName(models.Model):
    username = models.CharField(max_length=80, unique=True)
    name = models.CharField(max_length=200, blank=True, null=True)   #支持中文名字，可以为空
    passwd = models.CharField(max_length=200)
    USER_ROLE_CHOICES = (
        ('SU','SupUser'),
        ('CU','CommonUser'),
    )
    role = models.CharField(max_length=2, choices=USER_ROLE_CHOICES, default='CU')
    group = models.ManyToManyField(UserGroup)

    def __unicode__(self):
        return self.username

    def save(self, *args, **kwargs):
        # self.password = hashlib.sha1(self.password + self.birth).hexdigest()     #自定义加密方式
        self.passwd = make_password(self.passwd, 'a', 'pbkdf2_sha256')  # sha256加密
        super(UserName, self).save(*args, **kwargs)

class AssestGroup(models.Model):
    hostgroupname = models.CharField(max_length=200, unique=True)
    comment = models.CharField(max_length=200, blank=True, null=True)

    def __unicode__(self):
        return self.hostgroupname

class Assest(models.Model):
    hostname = models.CharField(max_length=200, blank=True, null=True)
    ipaddr = models.CharField(max_length=200, unique=True)
    passwd_key = models.CharField(max_length=200)
    port = models.CharField(max_length=100)
    IDC = models.CharField(max_length=200, blank=True, null=True)
    assestgroup = models.ManyToManyField(AssestGroup)
    OS = models.CharField(max_length=50, blank=True, null=True)
    cpu_num = models.CharField(max_length=50, blank=True, null=True)
    mem_info = models.CharField(max_length=50, blank=True, null=True)
    HDD_CHOICES = (
        ('hdd', 'HDD'),
        ('ssd', 'SSD'),
    )
    hdd_type = models.CharField(max_length=3, choices=HDD_CHOICES, default='hdd')
    hdd_num = models.CharField(max_length=50, blank=True, null=True)
    comment = models.CharField(max_length=200, blank=True, null=True)

    def __unicode__(self):
        return self.hostname

class SysUser(models.Model):
    username = models.CharField(max_length=80, unique=True)
    user = models.ManyToManyField(UserName)
    usergroup = models.ManyToManyField(UserGroup)
    assest = models.ManyToManyField(Assest)
    assestgroup = models.ManyToManyField(AssestGroup)
    comment = models.CharField(max_length=200, blank=True, null=True)

    def __unicode__(self):
        return self.username

# Create your models here.
class Upload(models.Model):
    headImg = models.FileField(upload_to = './upload/')

    def __unicode__(self):
        return self.headImg