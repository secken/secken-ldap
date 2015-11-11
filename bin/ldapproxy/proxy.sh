#! /bin/sh  

basepath=$(cd `dirname $0`; pwd)

start(){  
	java -jar $basepath/bin/ldapproxy.jar &
}  

stop(){  
	ps -ef | grep java | grep ldapproxy.jar | awk '{print $2}' | while read pid  
do  
	kill -9 $pid  
done  
}  

case "$1" in  
	start)  
		start  
		;;  
	stop)  
		stop  
		;;    
	restart)  
		stop  
		start  
		;;  
	*)  
		printf 'Usage: %s {start|stop|restart}\n' "$prog" 
		exit 1  
		;;  
esac


