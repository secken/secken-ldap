package org.secken.proxy.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Properties;

public class SeckenConfig {

	public String name = "ldapproxy";
	public String loglevel;
	public String ProxyListenAddr = "0.0.0.0";
	public int ProxyListenPort;
	public boolean ProxyTLS;
	public String ProxyKeyStoreFile;
	public String ProxyKeyStorePassword;
	public String ProxyCertAlias;
	public boolean ProxyVerifyClient = false;

	public String RealTimeAuthURL;
	public String GetEventResultURL;
	public String PowerID;
	public String PowerKey;
	public int timeOut;
	public int interval;

	public String ProxyClientAddr;
	public int ProxyClientPort;
	public boolean ProxyClientTLS = false;

	public SeckenConfig(String filePath) throws Exception {
		InputStream is = new FileInputStream(filePath);
		Properties p = new Properties();
		p.load(is);
		is.close();

		this.loglevel = p.getProperty("loglevel");

		if (p.getProperty("ProxyListenPort") == null || "".equals(p.getProperty("ProxyListenPort"))) {
			throw new Exception("please specify the 'ProxyListenPort' in config file '" + filePath + "'.");
		} else {
			this.ProxyListenPort = Integer.parseInt(p.getProperty("ProxyListenPort"));
		}

		String proxyTls = p.getProperty("ProxyTLS");
		if (proxyTls != null) {

			if ("".equals(proxyTls)) {
				throw new Exception("please specify the 'ProxyTLS' in config file '" + filePath + "'.");
			}

			if ("yes".equals(proxyTls)) {
				this.ProxyTLS = true;

				this.ProxyKeyStoreFile = p.getProperty("ProxyKeyStoreFile");
				if (this.ProxyKeyStoreFile == null || "".equals(this.ProxyKeyStoreFile)) {
					throw new Exception(
							"If you want enable proxy TLS, please specify the 'ProxyKeyStoeFile' in config file '"
									+ filePath + "'.");
				} else {
					if (!new File(this.ProxyKeyStoreFile).exists()) {
						throw new Exception("ProxyKeyStoeFile '" + ProxyKeyStoreFile
								+ "' dons't exist, please check your config file '" + filePath + "'.");
					}
				}

				this.ProxyKeyStorePassword = p.getProperty("ProxyKeyStorePassword");
				if (this.ProxyKeyStorePassword == null || "".equals(this.ProxyKeyStorePassword)) {
					throw new Exception(
							"if you want enable proxy TLS, please specify the 'ProxyKeyStorePassword' in config file '"
									+ filePath + "'.");
				}

				this.ProxyCertAlias = p.getProperty("ProxyCertAlias");
				if (this.ProxyCertAlias == null || "".equals(this.ProxyCertAlias)) {
					throw new Exception(
							"if you want enable proxy TLS, please specify the 'ProxyCertAlias' in config file '"
									+ filePath + "'.");
				}

				if (null != p.getProperty("ProxyVerifyClient") || !"".equals(p.getProperty("ProxyVerifyClient"))) {
					if ("yes".equals(p.getProperty("ProxyVerifyClient"))) {
						this.ProxyVerifyClient = true;
					} else if ("no".equals(p.getProperty("ProxyVerifyClient"))) {
						this.ProxyVerifyClient = false;
					} else {
						throw new Exception(
								"if you want verify client, please specify the 'ProxyVerifyClient=yes/no' in config file '"
										+ filePath + "'.");
					}
				}

			} else if ("no".equals(p.getProperty("ProxyTLS"))) {
				this.ProxyTLS = false;
			} else {
				throw new Exception(
						"config option 'ProxyTLS' must be 'yes' or 'no' in config file '" + filePath + "'.");
			}
		}

		if (p.getProperty("RealTimeAuthURL") == null || "".equals(p.getProperty("RealTimeAuthURL"))) {
			throw new Exception("please specify the 'RealTimeAuthURL' in config file '" + filePath + "'.");
		} else {
			this.RealTimeAuthURL = p.getProperty("RealTimeAuthURL");
		}
		if (p.getProperty("GetEventResultURL") == null || "".equals(p.getProperty("GetEventResultURL"))) {
			throw new Exception("please specify the 'GetEventResultURL' in config file '" + filePath + "'.");
		} else {
			this.GetEventResultURL = p.getProperty("GetEventResultURL");
		}
		if (p.getProperty("PowerID") == null || "".equals(p.getProperty("PowerID"))) {
			throw new Exception("please specify the 'PowerID' in config file '" + filePath + "'.");
		} else {
			this.PowerID = p.getProperty("PowerID");
		}
		if (p.getProperty("PowerKey") == null || "".equals(p.getProperty("PowerKey"))) {
			throw new Exception("please specify the 'PowerKey' in config file '" + filePath + "'.");
		} else {
			this.PowerKey = p.getProperty("PowerKey");
		}
		if (p.getProperty("timeout") == null || "".equals(p.getProperty("timeout"))) {
			throw new Exception("please specify the 'timeout' in config file '" + filePath + "'.");
		} else {
			this.timeOut = Integer.parseInt(p.getProperty("timeout"));
		}
		if (p.getProperty("interval") == null || "".equals(p.getProperty("interval"))) {
			throw new Exception("please specify the 'interval' in config file '" + filePath + "'.");
		} else {
			this.interval = Integer.parseInt(p.getProperty("interval"));
		}

		this.ProxyClientAddr = p.getProperty("AuthServerAddr");
		if (this.ProxyClientAddr == null || "".equals(this.ProxyClientAddr)) {
			throw new Exception("please specify the 'AuthServerAddr' in config file '" + filePath + "'.");
		}

		if (p.getProperty("AuthServerPort") == null || "".equals(p.getProperty("AuthServerPort"))) {
			throw new Exception("please specify the 'AuthServerPort' in config file '" + filePath + "'.");
		} else {
			this.ProxyClientPort = Integer.parseInt(p.getProperty("AuthServerPort"));
		}

		if (null != p.getProperty("AuthServerTLS") && !"".equals(p.getProperty("AuthServerTLS"))) {
			if ("yes".equals(p.getProperty("AuthServerTLS"))) {
				this.ProxyClientTLS = true;
			} else if ("no".equals(p.getProperty("AuthServerTLS"))) {
				this.ProxyClientTLS = false;
			} else {
				throw new Exception("config option 'AuthServerTLS' must be 'yes' or 'no' (default 'no') in config  '"
						+ filePath + "'.");
			}
		}
	}
}
