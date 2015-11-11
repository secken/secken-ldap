Introduction
============

一、目录结构:
	1.主目录结构
		rootdir
			|--bin   			由ldapproxy编译生成的软件目录
			|--code  			ldapproxy源码所在目录
			|--UPDATE.last		更新文档
			|--README.md		介绍文档

	2.ldapproxy软件目录结构(rootdir/bin)
		ldapproxy
			|--bin   			ldapproxy.jar所在目录
			|--conf 			配置文件所在目录
			|--logs				log所在目录(初始为空)
			|--certs			证书存放目录
			|--run				运行时文件目录
			|--version			版本文件所在目录
			|--ldapproxy.sh		启动脚本


二、依赖环境:
	1.服务器: 支持装有windows server、 linux的操作系统的服务器
	2.需手动安装java支持环境
	3.需为软件所需端口开启防火墙限制


三、如何编译:
	* 编译需要本地有java环境、maven工具支持 *
	1、通过eclipse进行编译
		通过eclipse以Existing Maven Projects工程进行导入
		在工程图标处单击右键，在菜单中选择 Run As -> Maven insatll
		清除工程请在工程图标处单击右键，在菜单中选择 Run As -> Maven clean

	2.通过命令行进行编译
		进入rootdir/code/
		执行 maven install 编译工程
		执行 maven clean 清除工程

	3.编译出的软件包的位置为rootdir/code/target/ldapproxy


四、如何安装\执行:
	1.将bin目录下的ldapproxy目录拷贝到你想放置的目录
	2.linux：进入ldapproxy，执行./ldapproxy.sh start
	3.windows: 通过cmd命令行进入ldapproxy目录，执行ldapproxy.bat start


五、secken配置文件配置指导：
	1.代理模块相关配置
		ProxyListenPort 		(number)			代理监听端口
		ProxyTLS	 			(string yes/no)		代理是否启用TLS加密,若启用
		ProxyKeyStoreFile 		(string)			keystore文件所在路径
		ProxyKeyStorePassword 	(string)			keystore文件密码
		ProxyCertAlias	 		(string)			keysotre文件中储存的Key的别名

	2.洋葱云认证相关配置
		RealTimeAuthURL 		(string)			认证请求接口，由内网管理中心提供
		GtEventResultURL		(string)			结果查询接口，由内网管理中心提供
		PowerID					(string)			权限ID，由内网管理中心提供
		PowerKey				(string)			权限key，有内网管理中心提供
		timeout					(number)			认证超时时间(以秒为单位)，在认证请求发起后，会在该时间内持续查询认证结果
													若超过该时间仍未得到认证结果，则本次认证视为失败，并向客户端返回
		interval 				(number)			查询间隔(以秒为单位)，在认证超时时间内，查询结果的间隔，建议时间为2秒

	3.认证服务器相关配置
		AuthServerAddr 			(string)			认证服务器地址，可填写域名或ip地址
		AuthServerPort 			(number)			认证服务器端口，
		AuthServerTLS  			(string yes/no)		认证服务器是否启用TLS加密

	4.log文件配置选项：
		loglevel 				(string)			log记录等级(非必填项)，可填字段为info/debug/error，默认为info

六、服务器端keystore文件生成方法：
	* keystore文件为java文件存储ssl秘钥的文件格式 *

	1.生成keysotre文件
		keytool -genkey -alias server -keystore server.keystore  

	2.从keystore文件中导出证书
		keytool -export -alias server -file server.cert -keystore server.keystore  

	* 更多关于keystore文件的信息请查询keystore文件或keytool命令 *
