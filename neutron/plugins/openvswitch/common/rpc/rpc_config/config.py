# -*- coding: UTF-8 -*-
"""
功    能：RpcClient类，rpc客户端启动类
版权信息：华为技术有限公司，版本所有(C) 2014
作者：
修改记录：2014-12-22 14:30  配置信息 创建
"""

# 连接正常时的重连检测间隔时间&心跳间隔时间
reconnect_monitor_time = 10
# 心跳的超时时间
echo_timeout = 2
# 没有连接时的重连间隔时间
reconnect_time = 5
# rpc client的最大线程数量
rpc_client_max_workers = 4
# rpc处理信息的最大线程数量
rpc_handle_max_workers = 5
# rpc线程池开启失败重试次数
rpc_reSubmit_ThreadPool_times = 10
# rpc请求默认超时时间
rpc_default_timeout = 10
# socket超时时间
socket_timeout = 10
# 心跳内容
echo_content = "echo"
# 启动心跳线程的间隔
DEFAULT_PERIOD = 0