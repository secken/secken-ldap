package org.secken.proxy.ldapproxy;

import java.io.IOException;

import org.apache.log4j.Logger;
import org.forgerock.opendj.ldap.LDAPConnectionFactory;
import org.forgerock.opendj.ldap.LDAPListener;
import org.secken.proxy.auth.SeckenAuthFactory;
import org.secken.proxy.config.SeckenConfig;

public class LDAPProxy {
	private SeckenConfig conf;
	private LDAPListener listener = null;
	private boolean isRuning = false;
	Logger LOGGER;

	LDAPProxy(SeckenConfig conf) throws Exception {
		this.conf = conf;
		LOGGER = Logger.getLogger(LDAPProxy.class);
		LOGGER.debug("logger start.");
	}

	public void start() {

		LDAPProxyConnectionFactory proxyConnectionFactory = null;
		try {
			LDAPConnectionFactory authServerConnectionFactory = LDAPAuthServer.getConnectionFactory(conf);
			SeckenAuthFactory authFacotry = new SeckenAuthFactory(conf);
			proxyConnectionFactory = new LDAPProxyConnectionFactory(conf, authServerConnectionFactory, authFacotry);
		} catch (Exception e) {
			LOGGER.error(e.getMessage());
			LOGGER.error("Error listening on " + conf.ProxyListenAddr + ":" + conf.ProxyListenPort);
			return;
		}

		try {
			listener = new LDAPListener(conf.ProxyListenAddr, conf.ProxyListenPort, proxyConnectionFactory);

			LOGGER.info("LDAPProxy successful listening at " + conf.ProxyListenAddr + ":" + conf.ProxyListenPort);
			this.isRuning = true;

		} catch (IOException e) {
			LOGGER.error("Error listening on " + conf.ProxyListenAddr + ":" + conf.ProxyListenPort);
			LOGGER.error(e.getMessage(), e);
			if (listener != null) {
				listener.close();
			}
			return;
		}
	}

	public LDAPListener GetListener() {
		return listener;
	}

	public boolean IsRunning() {
		return isRuning;
	}
}
