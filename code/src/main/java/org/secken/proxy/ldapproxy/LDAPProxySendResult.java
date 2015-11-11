package org.secken.proxy.ldapproxy;

import org.apache.log4j.Logger;
import org.forgerock.opendj.ldap.LdapResultHandler;
import org.forgerock.opendj.ldap.ResultCode;
import org.forgerock.opendj.ldap.responses.BindResult;
import org.secken.proxy.auth.SeckenAuthResult;

public class LDAPProxySendResult implements SeckenAuthResult {
	private BindResult result;
	private LdapResultHandler<BindResult> resultHandler;
	Logger logger = Logger.getLogger(LDAPProxySendResult.class);
	
	LDAPProxySendResult(BindResult result, LdapResultHandler<BindResult> resultHandler) {
		this.result = result;
		this.resultHandler = resultHandler;
	}
	

	public void onSuccess(String username) {
		logger.info("[" + username + "] auth SUCCESS.");

		resultHandler.handleResult(result);
	}

	public void onExpection(String username) {
		logger.info("[" + username + "] auth FAILED.");

		resultHandler.handleResult(result.setResultCode(ResultCode.INVALID_CREDENTIALS));
		
	}

	public void onTimeOut(String username) {
		logger.info("[" + username + "] auth TIME OUT.");

		resultHandler.handleResult(result.setResultCode(ResultCode.INVALID_CREDENTIALS));		
	}

}
