package org.secken.proxy.auth;

import java.util.Timer;
import java.util.TimerTask;

import org.apache.log4j.Logger;
import org.secken.api.SeckenAPI;

public class SeckenAuth {
	private String authURL;
	private String resultURL;
	private String id;
	private String key;
	private boolean privateAuth = true;
	private TimerTask timeTask = null;
	private SeckenAuthResult sendResult;
	private SeckenAuthRecorder recorder;

	Logger logger = Logger.getLogger(SeckenAuth.class);

	public SeckenAuth(String authURL, String resultURL, String id, String key, boolean privateAuth,
			SeckenAuthResult sendResult, SeckenAuthRecorder recorder) {
		this.authURL = authURL;
		this.resultURL = resultURL;
		this.id = id;
		this.key = key;
		this.privateAuth = privateAuth;
		this.sendResult = sendResult;
		this.recorder = recorder;
	}

	private class EventTimerTask extends TimerTask {
		private int timeCount = 0;

		private String eventID;
		private int repeatInterval;
		private int timeOut;
		private String username;

		EventTimerTask(String eventID, int repeatInterval, int timeOut, String username) {
			this.eventID = eventID;
			this.repeatInterval = repeatInterval;
			this.timeOut = timeOut;
			this.username = username;
		}

		@Override
		public void run() {
			try {
				int retCode = SeckenAPI.GetEventResult(resultURL, id, key, this.eventID);
				if (retCode != 602 && retCode != 201) {
					if (retCode == 200) {
						sendResult.onSuccess(username);
					} else {
						sendResult.onExpection(username);
					}
					logger.debug("[" + username +  "] get auth result code [" + retCode + "].");
					CancleTimer(username);
				} else {
					this.timeCount = this.timeCount + repeatInterval;
					if (this.timeCount >= timeOut) {
						sendResult.onTimeOut(username);

						CancleTimer(username);
					}
				}
			} catch (Exception e) {
				sendResult.onExpection(username);
				logger.error(e.getMessage(), e);

				CancleTimer(username);
			}
		}

		private void CancleTimer(String username) {
			logger.info("[" + username + "] Auth in secken is finished.");
			recorder.remove(username);
			cancel();
		}

	}

	public void Auth(String username, Timer timer, int repeatInterval, int timeOut) {

		if (this.privateAuth == true) {
			try {
				String eventID = SeckenAPI.RealtimeAuthPrivate(this.authURL, this.id, this.key, username);
				this.timeTask = new EventTimerTask(eventID, repeatInterval, timeOut, username);
				timer.schedule(timeTask, repeatInterval * 1000, repeatInterval * 1000);
				recorder.put(username, this);
				logger.info("[" + username + "] start secken auth.");
			} catch (Exception e) {
				sendResult.onExpection(username);
				logger.error("[" + username + "] start secken auth error, " + e.getMessage());
			}
		}
	}

	public void CancleAuth() {
		this.timeTask.cancel();
	}
}
