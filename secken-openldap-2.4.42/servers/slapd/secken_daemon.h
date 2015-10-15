#ifndef __SECKEN_DAEMON_H__
#define __SECKEN_DAEMON_H__

typedef void (*send_resp_t)(int result, void *args);
 
#define SK_AUTH_SUCCESS 0
#define SK_AUTH_FAILED -1

#define MAX_UNAME_LEN 		2048
#define MAX_EVENT_ID_LEN 	64

int secken_daemon_start(char *conf_file);

int secken_daemon_do_auth(
		int fd, 
		char *username, 
		send_resp_t send_resp,
		void *args);

int secken_daemon_cancel_auth(int fd);

#endif 
