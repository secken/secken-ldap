package org.secken.proxy.auth;

import java.util.HashMap;

import org.apache.log4j.Logger;

public class SeckenAuthRecorder {
	private HashMap<String, SeckenAuth> authRecorder;
	Logger logger = Logger.getLogger(SeckenAuthRecorder.class);

	SeckenAuthRecorder() {
		authRecorder = new HashMap<String, SeckenAuth>();
	}

	public void put(String username, SeckenAuth seckenAuth) {
		logger.debug("add " + username + " to auth recorder");

		authRecorder.put(username, seckenAuth);
	}

	public boolean remove(String username) {
		if (authRecorder.containsKey(username)) {
			logger.debug("remove " + username + " from auth recorder");

			authRecorder.get(username).CancleAuth();
			authRecorder.remove(username);
			return true;
		}
		logger.debug("remove " + username + " from auth recorder, but recorder dosen't has it");
		return false;
	}

	public boolean containsKey(String username) {
		return authRecorder.containsKey(username);
	}
}
