# -*- coding: UTF-8 -*-
"""
            功    能：Callback类，回调函数的父类
            版权信息：华为技术有限公司，版本所有(C) 2014
            作者：
            修改记录：2014-11-3 14:30  Callback 创建
"""


class Callback():
    def __init__(self):
        pass

    def returnSuccess(self, address, result):
        pass

    def returnFail(self, address, error):
        pass