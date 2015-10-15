#ifndef __SLAPD_EXTERNAL_H__
#define __SLAPD_EXTERNAL_H__

typedef int (*send_ldap_t)( Sockbuf *sb, BerElement *ber, int freeit );

int slapd_external_proc_auth(
		char *dn, 
		Sockbuf *sb,
		BerElement *s_ber,
		BerElement *f_ber, 
		send_ldap_t send_ldap_r);

int slapd_external_cancel_auth(int fd);

int slapd_external_init(char *conf_file);

#endif
