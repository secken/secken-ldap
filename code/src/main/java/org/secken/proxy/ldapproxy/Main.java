package org.secken.proxy.ldapproxy;

import java.io.IOException;

import org.apache.log4j.FileAppender;
import org.apache.log4j.Level;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.secken.proxy.config.SeckenConfig;

public class Main {

	private static void initLog4j(String path, SeckenConfig conf) throws IOException {
		Logger rootLogger = LogManager.getRootLogger();
		PatternLayout p = new PatternLayout("%-d{yyyy-MM-dd HH:mm:ss} - [%t] : [%p] %m%n");
		FileAppender fa = new FileAppender(p, path + "/logs/ldapproxy.log");
		rootLogger.addAppender(fa);

		if ("debug".equals(conf.loglevel)) {
			rootLogger.setLevel(Level.DEBUG);
		} else if ("info".equals(conf.loglevel)) {
			rootLogger.setLevel(Level.INFO);
		} else if ("error".equals(conf.loglevel)) {
			rootLogger.setLevel(Level.ERROR);
		} else if (conf.loglevel == null || "".equals(conf.loglevel)) {
			rootLogger.setLevel(Level.INFO);
		}
	}

	public static void main(String[] args) {
		String path = null;

		if (args.length == 1) {
			path = args[0];
		} else {
			System.exit(-1);
		}

		LDAPProxy proxy = null;

		try {
			String confFile = path + "/conf/secken-default.conf";
			SeckenConfig conf = new SeckenConfig(confFile);
			initLog4j(path, conf);
			proxy = new LDAPProxy(conf);
		} catch (Exception e) {
			System.err.println("");
			System.err.println("[ WARNING! ] secken-ldapproxy exit normally. " + e.getMessage());
			System.exit(-1);
		}

		proxy.start();

		if (proxy.IsRunning() == false) {
			System.err.println("");
			System.err.println("[ WARNING! ] secken-ldapproxy exit normally, please see more info in err.log.");
			System.exit(-1);
		} else {
			System.err.println("");
			System.err.println("[ SUCCESS! ] secken-ldapproxy start.");
			while (true) {
				try {
					Thread.sleep(3000);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
			}
		}
	}

}
