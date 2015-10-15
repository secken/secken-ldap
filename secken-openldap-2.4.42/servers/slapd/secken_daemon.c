/* 		
		secken auth flow

		server

		^	   |
		|    3
		2    |
		|	   v			1¡¢					2¡¢
		|--------|				
		|  ldap  | -- 4-->	rcv_do_auth	  - - >	timer_out <- - - - - - -				
		|   ro   |				|		  |			|					|
		| radius |				v					v
		|--------|			auth_req 	  |		result_req				|
		^						|					|
		|						v		  |			v		 fail		|
		|					auth_resp			result_resp - - - -> add_timer
		1						|		  |			| success
		| 					v					v
		|					add_timer - - |		send_do_auth
		|											|
		|
		client  <---------------- 5 ---------------|

*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <pthread.h>
#include <event.h>
#include <assert.h>

#include "secken_daemon.h"
#include "ccl.h"

static int g_result_interval;
static int g_timeout;
static char g_auth_url[1024];
static char g_result_url[1024];
static char g_power_id[128];
static char g_power_key[128];

#define INVALID_HANDLE -1

typedef struct _strval_t {
	unsigned int len;
	char *val;
} strval_t;

enum daemon_action_t {
	DAEMON_ACTION_MIN,
	DAEMON_ACTION_DO_AUTH,
	DAEMON_ACTION_CANCEL_AUTH,
	DAEMON_ACTION_MAX
};

typedef int handle_t;

typedef struct _do_auth_t {
	handle_t h;
	char uname[MAX_UNAME_LEN];
	send_resp_t send_resp;
	void *args;
} do_auth_t;

typedef struct _cancel_auth_t {
	handle_t h;
} cancel_auth_t;

typedef struct _daemon_data_t {
	int tag;
	union {
		do_auth_t auth;
		cancel_auth_t cancel;
	} val;
} daemon_data_t;

typedef struct _auth_data_t {
	char uname[MAX_UNAME_LEN];
	char event_id[MAX_EVENT_ID_LEN];
} auth_data_t;

typedef struct _auth_handle_t {
	handle_t h;
	int interval;
	int time_count;
	struct event *ev;
	auth_data_t auth_data;
	void *args;
	send_resp_t send_resp;
} auth_handle_t;

auth_handle_t **g_auth_handle_set;
#define GET_AUTH_HANDLE(i) g_auth_handle_set[i]
#define SET_AUTH_HANDLE(hdl) g_auth_handle_set[hdl->h] = hdl
#define CLR_AUTH_HANDLE(h) g_auth_handle_set[h] = NULL
#define IS_AUTH_HANDLE_VALID(h) (g_auth_handle_set[h] ? 0 : 1)

#define MAX_SET_NUM 65536

static int g_servport = 1234;
static char g_servaddr[16] = "172.1.33.108";

int g_pfd[2];

static int is_digit_str(const char *s)
{
	while(*s) 
		if(!isdigit(*s++))
			return 0;

	return 1;
}

static handle_t create_auth_handle(do_auth_t *auth, char *event_id)
{
	auth_handle_t *hdl;

	assert(NULL == GET_AUTH_HANDLE(auth->h));

	hdl = (auth_handle_t *)malloc(sizeof(auth_handle_t));
	if (NULL == hdl) 
		return INVALID_HANDLE;
	memset(hdl, 0, sizeof(auth_handle_t));

	hdl->h = auth->h;

	if (strlen(hdl->auth_data.uname) > MAX_UNAME_LEN - 1) {
		free(hdl->ev);
		free(hdl);
		return INVALID_HANDLE;
	}
	strcpy(hdl->auth_data.uname, auth->uname);

	if (strlen(event_id) > MAX_EVENT_ID_LEN - 1) {
		free(hdl->ev);
		free(hdl);
		return INVALID_HANDLE;
	}
	strcpy(hdl->auth_data.event_id, event_id);

	hdl->interval = g_result_interval;
	hdl->time_count = 0;
	hdl->args = auth->args;
	hdl->send_resp = auth->send_resp;

	SET_AUTH_HANDLE(hdl);

	return hdl->h;
}

static void destory_auth_handle(handle_t h)
{
	auth_handle_t *hdl = GET_AUTH_HANDLE(h);

	if (hdl == NULL) {
		return;
	}

	assert(hdl->h == h);

	if (hdl->ev != NULL) {
		event_del(hdl->ev);
		free(hdl->ev);
	}

	free(hdl);

	CLR_AUTH_HANDLE(h);
}

static void secken_daemon_auth_timer_handler(const int fd, const short event, void *args);

static int add_auth_timer(handle_t h) 
{
	auth_handle_t *hdl = GET_AUTH_HANDLE(h); 
	struct timeval tv;

	assert(hdl != NULL);
	assert(hdl->h == h);

	hdl->ev = (struct event *)malloc(sizeof(struct event));
	if (NULL == hdl->ev) 
		return -1;
	memset(hdl->ev, 0, sizeof(struct event));

	hdl->time_count += hdl->interval;

	tv.tv_sec = hdl->interval;
	tv.tv_usec = 0;
	evtimer_set(hdl->ev, secken_daemon_auth_timer_handler, (void *)(long)h);
	evtimer_add(hdl->ev, &tv);

	return 0;
}

static void secken_daemon_auth_timer_handler(const int fd, const short event, void *args)
{
	int status;
	int result;
	char *event_id;
	handle_t h = (long)args;
	auth_handle_t *hdl = GET_AUTH_HANDLE(h);

	assert( hdl->h == h );

	event_id = hdl->auth_data.event_id;

	if ( 0 == secken_event_req( g_result_url, g_power_id, g_power_key, event_id, &status ) ) {
		if ( 200 == status ) {
			/* status == 200 means that somthing auth pass */
			result = SK_AUTH_SUCCESS;
			goto send_result;
		} else if ( 602 != status && 201 != status) { 
			/* status != 602 means that somthing err */
			result = SK_AUTH_FAILED;
			goto send_result;
		}
	}

	add_auth_timer( h );

	return;

send_result:
	hdl->send_resp( result, hdl->args );
	destory_auth_handle( h );
}

static void secken_daemon_auth(do_auth_t *auth)
{
	char event_id[64];
	handle_t h;

	assert(auth != NULL);

	if (!IS_AUTH_HANDLE_VALID(auth->h)) {
		fprintf(stderr, "[EXTERNAL] Sock %d is already process in external\n", auth->h);
		return;
	}

	memset(event_id, 0, sizeof(event_id));
	if (0 != secken_auth_req(g_auth_url, g_power_id, g_power_key, auth->uname, event_id) ) 
		goto auth_err;
	if (0 >= strlen(event_id)) 
		goto auth_err;

	h = create_auth_handle(auth, event_id);
	if (h == INVALID_HANDLE) {
		fprintf(stderr, "%s: create socket err\n", __func__);
		goto auth_err;
	}

	fprintf(stderr, "[EXTERNAL] Sock %d is start quary %s auth from secken\n", auth->h, auth->uname);
	if (-1 == add_auth_timer( h ))
		goto auth_err;

	return;

auth_err:
	auth->send_resp(SK_AUTH_FAILED, auth->args);
	destory_auth_handle( h );
}

static void secken_daemon_auth_cancel(cancel_auth_t *cancel)
{
	destory_auth_handle(cancel->h);
}

static void secken_daemon_handler(const int fd, const short ev, void *arg)
{
	char buf[8192];

	daemon_data_t *data;

	if (1 > read(fd, buf, sizeof(buf)))
		return;

	data = (daemon_data_t*)&buf;
	switch (data->tag) {
	case DAEMON_ACTION_DO_AUTH:
		secken_daemon_auth(&data->val.auth);
		break;
	case DAEMON_ACTION_CANCEL_AUTH:
		secken_daemon_auth_cancel(&data->val.cancel);
		break;
	default:
		fprintf(stderr, "secken daemon: %s: recv unknow tag\n", __func__);
		break;
	}
}

static void *secken_daemon_main(void *args)
{
	struct event pipe_ev;

	if (!event_init()) 
		return;

	memset(&pipe_ev, 0, sizeof(pipe_ev));
	event_set(&pipe_ev, g_pfd[0], EV_READ|EV_PERSIST, secken_daemon_handler, NULL);
	event_add(&pipe_ev, NULL);

	event_dispatch();
}

static int secken_daemon_config_init(char *conf_file)
{
	int ret;
	struct ccl_t conf;
	const char *val;

	conf.comment_char = '#';
	conf.sep_char = '=';
	conf.str_char = '"';

	ret = ccl_parse(&conf, conf_file);
	if (0 != ret)
		return -1;

	val = ccl_get(&conf, "timeout");
	if (!val || !is_digit_str(val)) 
		return -1;
	sscanf(val, "%d", &g_timeout);

	val = ccl_get(&conf, "result_req_interval");
	if (!val || !is_digit_str(val)) 
		return -1;
	sscanf(val, "%d", &g_result_interval);

	val = ccl_get(&conf, "auth_req_url");
	if (!val || strlen(val) > sizeof(g_auth_url)) 
		return -1;
	strcpy(g_auth_url, val);

	val = ccl_get(&conf, "result_req_url");
	if (!val || strlen(val) > sizeof(g_result_url)) 
		return -1;
	strcpy(g_result_url, val);

	val = ccl_get(&conf, "power_id");
	if (!val || strlen(val) > sizeof(g_power_id)) 
		return -1;
	strcpy(g_power_id, val);

	val = ccl_get(&conf, "power_key");
	if (!val || strlen(val) > sizeof(g_power_key)) 
		return -1;
	strcpy(g_power_key, val);

	fprintf(stderr, "---------parse config--------\n");
	fprintf(stderr, "%s\n", conf_file);
	fprintf(stderr, "timeout = %d\n", g_timeout);
	fprintf(stderr, "result_req_interval = %d\n", g_result_interval);
	fprintf(stderr, "auth_req_url = %s\n", g_auth_url);
	fprintf(stderr, "result_req_url = %s\n", g_result_url);
	fprintf(stderr, "power_id = %s\n", g_power_id);
	fprintf(stderr, "power_key = %s\n", g_power_key);

	if (g_timeout < g_result_interval)
		return -1;

	if (strlen(g_auth_url) <= 0 ||
		strlen(g_result_url) <= 0 ||
		strlen(g_power_id) <= 0 ||
		strlen(g_power_key) <= 0)
		return -1;

	return 0;
}

int secken_daemon_start(char *conf_file)
{
	pthread_t tid;

	if (-1 == secken_daemon_config_init(conf_file))
		return -1;

	pipe(g_pfd);

	g_auth_handle_set = (void *)malloc(MAX_SET_NUM * sizeof(void *));
	memset(g_auth_handle_set, 0, MAX_SET_NUM * sizeof(void *));

	if (0 != pthread_create(&tid, NULL, secken_daemon_main, NULL))
		return -1;

	return 0;
}	

int secken_daemon_do_auth(int fd, char *username, send_resp_t send_resp, void *args)
{
	daemon_data_t data;

	memset(&data, 0, sizeof(data));
	data.tag = DAEMON_ACTION_DO_AUTH;
	data.val.auth.h = fd;

	if (strlen(username) > MAX_UNAME_LEN - 1) 
		return -1;

	strcpy(data.val.auth.uname, username);
	
	data.val.auth.send_resp = send_resp;
	data.val.auth.args = args;

	return write(g_pfd[1], &data, sizeof(data));
}

int secken_daemon_cancel_auth(int fd)
{
	daemon_data_t data;

	memset(&data, 0, sizeof(data));
	data.tag = DAEMON_ACTION_CANCEL_AUTH;
	data.val.cancel.h = fd;

	return write(g_pfd[1], &data, sizeof(data));
}
