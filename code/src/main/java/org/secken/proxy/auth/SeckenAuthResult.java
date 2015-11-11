package org.secken.proxy.auth;

public interface SeckenAuthResult {
	
	public abstract void onSuccess(String username);
	
	public abstract void onExpection(String username);
	
	public abstract void onTimeOut(String username);
	
}
