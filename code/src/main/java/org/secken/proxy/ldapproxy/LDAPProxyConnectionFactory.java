package org.secken.proxy.ldapproxy;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.apache.log4j.Logger;
import org.forgerock.opendj.ldap.KeyManagers;
import org.forgerock.opendj.ldap.LDAPClientContext;
import org.forgerock.opendj.ldap.LDAPConnectionFactory;
import org.forgerock.opendj.ldap.LdapException;
import org.forgerock.opendj.ldap.SSLContextBuilder;
import org.forgerock.opendj.ldap.ServerConnection;
import org.forgerock.opendj.ldap.ServerConnectionFactory;
import org.forgerock.opendj.ldap.TrustManagers;
import org.secken.proxy.auth.SeckenAuthFactory;
import org.secken.proxy.config.SeckenConfig;

public class LDAPProxyConnectionFactory implements ServerConnectionFactory<LDAPClientContext, Integer> {

	private boolean enableTLS = false;
	private SSLContext serverSSLContext;
	private LDAPConnectionFactory authServerConnectionfactory;
	private SeckenAuthFactory authFacotry;

	private Logger logger = Logger.getLogger(LDAPProxyConnectionFactory.class);

	LDAPProxyConnectionFactory(SeckenConfig conf, LDAPConnectionFactory authServerConnectionfactory,
			SeckenAuthFactory authFacotry) throws Exception {
		this.authServerConnectionfactory = authServerConnectionfactory;
		this.authFacotry = authFacotry;

		this.enableTLS = conf.ProxyTLS;
		if (this.enableTLS == true) {
			if ((this.serverSSLContext = CreateSSLContext(conf)) == null) {
				throw new Exception("Create ssl context error.");
			}
		}
	}

	public ServerConnection<Integer> handleAccept(LDAPClientContext clientContext) {
		if (this.enableTLS == true) {
			clientContext.enableTLS(serverSSLContext, null, null, false, false);
		}

		try {
			logger.debug("Connection from: " + clientContext.getPeerAddress() + " TLSenable:" + this.enableTLS);
			return new LDAPProxyConnection(clientContext, this.authServerConnectionfactory, this.authFacotry);
		} catch (LdapException e) {
			logger.error(e.getMessage(), e);
			return null;
		}

	}

	private SSLContext CreateSSLContext(SeckenConfig conf) {
		SSLContext SSLContext = null;

		X509KeyManager x509KeyManager = null;
		try {
			x509KeyManager = KeyManagers.useKeyStoreFile(conf.ProxyKeyStoreFile,
					conf.ProxyKeyStorePassword.toCharArray(), null);
		} catch (GeneralSecurityException e) {
			logger.error(e.getMessage(), e);
		} catch (IOException e) {
			logger.error(e.getMessage(), e);
		}

		if (x509KeyManager.getPrivateKey(conf.ProxyCertAlias) == null) {
			logger.error("PROXY [" + conf.name + "] don't have key " + conf.ProxyCertAlias + " in cert");
			return null;
		}
		KeyManager keyManager = KeyManagers.useSingleCertificate(conf.ProxyCertAlias, x509KeyManager);

		X509TrustManager trustManager = null;
		if (conf.ProxyVerifyClient == true) {
			logger.error("ProxyVerifyClient not supported yet, please remove ProxyVerifyClient in config file");
			return null;
			// trustManager.checkClientTrusted(chain, authType);
			// TrustManagers.checkUsingTrustStore(file, password, format);
			// trustManager.checkClientTrusted(chain, authType);
		} else {
			trustManager = TrustManagers.trustAll();
		}

		SSLContextBuilder builder = new SSLContextBuilder();
		builder = builder.setKeyManager(keyManager);
		builder = builder.setTrustManager(trustManager);

		try {
			SSLContext = builder.getSSLContext();
		} catch (GeneralSecurityException e) {
			logger.error(e.getMessage(), e);
		}

		return SSLContext;
	}

}
