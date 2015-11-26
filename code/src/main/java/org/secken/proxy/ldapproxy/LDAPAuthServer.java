package org.secken.proxy.ldapproxy;

import static org.forgerock.opendj.ldap.LDAPConnectionFactory.SSL_CONTEXT;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import org.apache.log4j.Logger;
import org.forgerock.opendj.ldap.Connection;
import org.forgerock.opendj.ldap.LDAPConnectionFactory;
import org.forgerock.opendj.ldap.LdapException;
import org.forgerock.opendj.ldap.ResultCode;
import org.forgerock.opendj.ldap.SSLContextBuilder;
import org.forgerock.opendj.ldap.TrustManagers;
import org.forgerock.util.Options;
import org.secken.proxy.config.SeckenConfig;

public class LDAPAuthServer {

	private static Logger logger = Logger.getLogger(LDAPAuthServer.class);

	public static LDAPConnectionFactory getConnectionFactory(SeckenConfig conf) throws Exception {
		LDAPConnectionFactory factory = null;

		if (conf.ProxyClientTLS) {
			try {
				Options options = getClientTrustAllOptions();

				if (options != null) {
					factory = new LDAPConnectionFactory(conf.ProxyClientAddr, conf.ProxyClientPort, options);
				} else {
					throw new Exception("Create security client connecion failed");
				}
			} catch (GeneralSecurityException e) {
				e.printStackTrace();
			}
		} else {
			factory = new LDAPConnectionFactory(conf.ProxyClientAddr, conf.ProxyClientPort);
		}

		logger.info("Trying to connecting auth server " + conf.ProxyClientAddr + ":" + conf.ProxyClientPort + " ...");

		if (isRemoteServerUsable(factory) == false) {
			logger.info("FAILED!");
			throw new Exception("remote Server " + conf.ProxyClientAddr + ":" + conf.ProxyClientPort + " unusable ");
		} else {
			logger.info("SUCCESS!");
		}

		return factory;
	}

	private static boolean isRemoteServerUsable(LDAPConnectionFactory factory) {

		try {
			Connection connection = factory.getConnection();
			if (connection == null)
				return false;

			connection.bind("", "".toCharArray());
			connection.close();
			return true;
		} catch (LdapException e) {
			if (e.getResult().getResultCode() == ResultCode.CLIENT_SIDE_CONNECT_ERROR) {
				return false;
			} else {
				return true;
			}
		}

	}

	@SuppressWarnings("unused")
	private static Options getTrustOptions(final String hostname, final String truststore, final String storepass)
			throws GeneralSecurityException {
		Options options = Options.defaultOptions();

		TrustManager trustManager = null;
		try {
			trustManager = TrustManagers.checkValidityDates(TrustManagers.checkHostName(hostname,
					TrustManagers.checkUsingTrustStore(truststore, storepass.toCharArray(), null)));
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(1);
		}

		if (trustManager != null) {
			SSLContext sslContext = new SSLContextBuilder().setTrustManager(trustManager).getSSLContext();
			options.set(SSL_CONTEXT, sslContext);
		}

//		options.set(USE_STARTTLS, false);

		return options;
	}

	private static Options getClientTrustAllOptions() throws GeneralSecurityException {
		Options options = Options.defaultOptions();
		SSLContext sslConetxt = new SSLContextBuilder().setTrustManager(TrustManagers.trustAll()).getSSLContext();
		options.set(SSL_CONTEXT, sslConetxt);
		// options.set(USE_STARTTLS, false);
		return options;
	}
}
