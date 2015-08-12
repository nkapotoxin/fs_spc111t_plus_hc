# -*- coding: UTF-8 -*-
"""
            功    能：ServerAware类，当有socket连接时的处理函数的父类
            版权信息：华为技术有限公司，版本所有(C) 2014
            作者：
            修改记录：2014-11-3 14:30  Future 创建
"""


class ServerAware:
    def __init__(self):
        pass

    def added(self, terminal):
        pass

    def removed(self, terminal):
        pass
