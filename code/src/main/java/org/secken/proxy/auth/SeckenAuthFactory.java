package org.secken.proxy.auth;

import java.util.Timer;

import org.apache.log4j.Logger;
import org.secken.proxy.config.SeckenConfig;

public class SeckenAuthFactory {
	private SeckenAuthRecorder recorder = new SeckenAuthRecorder();
	private Timer timer = new Timer();

	private String authURL;
	private String resultURL;
	private String id;
	private String key;
	private boolean privateAuth = true;
	private int timeOut;
	private int repeatInterval;
	
	Logger logger = Logger.getLogger(SeckenAuthFactory.class);

	public SeckenAuthFactory(SeckenConfig conf) {
		this.authURL = conf.RealTimeAuthURL;
		this.resultURL = conf.GetEventResultURL;
		this.id = conf.PowerID;
		this.key = conf.PowerKey;
		this.privateAuth = true;
		this.timeOut = conf.timeOut;
		this.repeatInterval = conf.interval;
	}

	public void StartAuth(String username, SeckenAuthResult sendResult) {
		if (!recorder.containsKey(username)) {
			SeckenAuth auth = new SeckenAuth(this.authURL, this.resultURL, this.id, this.key, this.privateAuth,
					sendResult, recorder);
			auth.Auth(username, this.timer, this.repeatInterval, this.timeOut);
		} else {
			logger.info("[" + username + "] already in secken auth.");
		}
	}

	public void CancleAuth(String username) {
		if (username == null)
			return;
		if (!recorder.remove(username)) {
			logger.info("Can not cancle because [" + username + "] not in secken auth.");
		}
	}
}
