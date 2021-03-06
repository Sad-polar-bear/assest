from django.conf.urls import url
from auser.views import *

urlpatterns = [
    url(r'^group/list/$', group_list, name='group_list'),
    url(r'^group/add/$', group_add, name='group_add'),
    url(r'^group/del/$', group_del, name='group_del'),
    url(r'^group/update/$', group_update, name='group_update'),
    url(r'^user/add/$', user_add, name='user_add'),
    url(r'^user/list/$', user_list, name='user_list'),
    url(r'^user/del/$', user_del, name='user_del'),
    url(r'^user/update/$', user_update, name='user_update'),
    url(r'^user/am/$', user_am, name='user_am'),
    url(r'^info/$',sys_info,name='sys_info'),
    url(r'^delSelect/$', delSelect, name='delSelect'),
    url(r'^deluserSelect/$', deluserSelect, name='deluserSelect'),
    url(r'^query/$', queryById, name='queryById'),
    url(r'^query_user/$', queryByuser, name='queryByuser'),
    url(r'^assestgroup/list/$', assestgroup_list, name='assestgroup_list'),
    url(r'^assestgroup/add/$', assestgroup_add, name='assestgroup_add'),
    url(r'^assestgroup/del/$', assestgroup_del, name='assestgroup_del'),
    url(r'^queryByAssestgroup/$', queryByAssestgroup, name='queryByAssestgroup'),
    url(r'^delassestgroupSelect/$', delassestgroupSelect, name='delassestgroupSelect'),
    url(r'^assestgroup/update/$', assestgroup_update, name='assestgroup_update'),
    url(r'^assest/list/$', assest_list, name='assest_list'),
    url(r'^assest/add/$', assest_add, name='assest_add'),
    url(r'^assest/del/$', assest_del, name='assest_del'),
    url(r'^assest/update/$', assest_update, name='assest_update'),
    url(r'^sysuser/list/$', sysuser_list, name='sysuser_list'),
    url(r'^sysuser/add/$', sysuser_add, name='sysuser_add'),
    url(r'^sysuser/del/$', sysuser_del, name='sysuser_del'),
    url(r'^sysuser/update/$', sysuser_update, name='sysuser_update'),
    url(r'^query_sysuser/$', queryBysysuser, name='queryBysysuser'),
    url(r'^delsysuserSelect/$', delsysuserSelect, name='delsysuserSelect'),
#    url(r'^push/$', push, name='push'),
    url(r'^ansible/config/$', ansible_config, name='ansible_config'),
    url(r'^index/$', index, name='index'),
    url(r'^upload/$', upload, name='upload'),
    url(r'^download/$', download, name='download'),
]