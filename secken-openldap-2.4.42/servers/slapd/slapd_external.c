#include "portable.h"
#include "slap.h"
#include "secken_daemon.h"
#include "slapd_external.h"
#include "../../libraries/liblber/lber-int.h"

typedef struct _ext_cb_data_t {
	BerElement *s_ber;
	BerElement *f_ber;
	Sockbuf *sb;
	send_ldap_t send_ldap_r;
} ext_cb_data_t;

Sockbuf *copy_sb(Sockbuf *ori_sb)
{
	Sockbuf *sb;

	sb = ber_sockbuf_alloc();
	if (sb == NULL)
		return NULL;

	sb->sb_opts.lbo_valid = ori_sb->sb_opts.lbo_valid;
	sb->sb_opts.lbo_options = ori_sb->sb_opts.lbo_options;
	sb->sb_opts.lbo_debug = ori_sb->sb_opts.lbo_debug;
	sb->sb_iod = ori_sb->sb_iod;
	sb->sb_fd = ori_sb->sb_fd;
	sb->sb_trans_needs_read = ori_sb->sb_trans_needs_read;
	sb->sb_trans_needs_write = ori_sb->sb_trans_needs_write;
#ifdef LDAP_PF_LOCAL_SENDMSG
	sb->sb_ungetlen = ori_sb->sb_ungetlen;
	memcpy(sb->sb_ungetbuf, ori_sb->sb_ungetbuf, 8);
#endif
	return sb;
}

static ext_cb_data_t *create_ext_data(
		Sockbuf *sb, 
		BerElement *s_ber, 
		BerElement *f_ber,
		send_ldap_t send_ldap_r)
{

	ext_cb_data_t *data;

	data = (ext_cb_data_t *)malloc(sizeof(ext_cb_data_t));
	if (NULL == data) {
		free(data);
		return -1;
	}
	
	memset(data, 0, sizeof(ext_cb_data_t));
	data->s_ber = s_ber;
	data->f_ber = f_ber;
	data->send_ldap_r = send_ldap_r;
	data->sb = copy_sb(sb);
	if (NULL == data->sb) {
		free(data);
		return -1;
	}

	return data;
}

static void destory_ext_data(ext_cb_data_t *data)
{
	
	if (NULL != data->sb)
		free(data->sb);
		
	if (NULL != data->s_ber)
		free(data->s_ber);

	if (NULL != data->f_ber)
		free(data->f_ber);	
		
	if (NULL != data)
		free(data);
}

void slapd_external_do_auth_cb(int result, void *args)
{
	ext_cb_data_t *data = (ext_cb_data_t *)args;

	if (result == SK_AUTH_SUCCESS)
		data->send_ldap_r( data->sb, data->s_ber, LBER_FLUSH_FREE_NEVER);
	else
		data->send_ldap_r(data->sb, data->f_ber, LBER_FLUSH_FREE_NEVER);

	destory_ext_data(data);
}

int slapd_external_dn_to_username(const char *dn, char *name, int len)
{
	char *pos_comma;
	char *pos_equal;

	if (strlen(dn) > len - 1)
		return -1;

	for (pos_comma = dn; *pos_comma != '\0' && *pos_comma != ','; pos_comma ++);
	if (*pos_comma == '\0')
		return -1;

	for (pos_equal = dn; *pos_equal != NULL && *pos_equal != '='; pos_equal ++);
	pos_equal ++;
	if (*pos_equal == '\0' || pos_equal >= pos_comma) 
		return -1;

	memcpy(name, pos_equal, pos_comma - pos_equal);

	return 0; 
}

/* 
 * return  0 -- proc in external 
 * return  1 -- continue 
 * return -1 -- error 
 */
int slapd_external_do_auth(
		char *dn, 
		Sockbuf *sb,
		BerElement *s_ber,
		BerElement *f_ber, 
		send_ldap_t send_ldap_r)
{
	int fd;
	char username[1024];
	ext_cb_data_t *data;

	memset(username, 0, sizeof(username));
	if (-1 == slapd_external_dn_to_username(dn, username, sizeof(username))) {
		Debug( LDAP_DEBUG_TRACE, "external: %s: dn is not right type for secken auht .\n", 
				__func__, 0, 0);
		return -1;
	}

	data = create_ext_data(sb, s_ber, f_ber, send_ldap_r);
	if (NULL == data) {
		Debug( LDAP_DEBUG_TRACE, "external: %s: create external data error.\n", 
				__func__, 0, 0);
		return -1;
	}
	
	if (0 > secken_daemon_do_auth(sb->sb_fd, username, slapd_external_do_auth_cb, data)) {
		Debug( LDAP_DEBUG_TRACE, "external: %s: write to secken daemon error.\n", 
				__func__, 0, 0);
		return -1;
	}

	Debug( LDAP_DEBUG_TRACE, "%s: proc in external.\n", __func__, 0, 0);

	return 0 ;
}

int slapd_external_cancel_auth(int fd)
{
	return secken_daemon_cancel_auth(fd);
}

int slapd_external_init(char *conf_file)
{
	return secken_daemon_start(conf_file);
}
