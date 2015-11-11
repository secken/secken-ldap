package org.secken.api;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import net.sf.json.JSONObject;

public class SeckenAPI {
	
	private static String SHA1(String decript) {
		try {
			MessageDigest digest = java.security.MessageDigest.getInstance("SHA-1");
			digest.update(decript.getBytes());
			byte messageDigest[] = digest.digest();

			StringBuffer hexString = new StringBuffer();

			for (int i = 0; i < messageDigest.length; i++) {

				String shaHex = Integer.toHexString(messageDigest[i] & 0xFF);

				if (shaHex.length() < 2) {
					hexString.append(0);
				}
				hexString.append(shaHex);
			}
			return hexString.toString();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return "";
	}

	public static int GetEventResult(String url, String powerID, String powerKey, String eventID)
			throws Exception {
		String signature = SHA1("event_id=" + eventID + "power_id=" + powerID + powerKey);

		Map<String, String> dataMap = new HashMap<String, String>();
		dataMap.put("power_id", powerID);
		dataMap.put("event_id", eventID);
		dataMap.put("signature", signature);

		JSONObject json = JSONObject.fromObject(new HttpRequestor().doPost(url, dataMap));
		
		return Integer.parseInt(json.getString("status"));
	}

	public static String RealtimeAuthPrivate(String url, String powerID, String powerKey, String name)
			throws Exception {
		
		String signature = SHA1("power_id=" + powerID + "username=" + name + powerKey);

		Map<String, String> dataMap = new HashMap<String, String>();
		dataMap.put("power_id", powerID);
		dataMap.put("username", name);
		dataMap.put("signature", signature);

		JSONObject json = JSONObject.fromObject(new HttpRequestor().doPost(url, dataMap));

		if (200 == Integer.parseInt(json.getString("status"))) {
			String returnEventID = json.getString("event_id");
			return returnEventID;

		} else {
			throw new Exception(json.getString("status") + " " + json.getString("description"));
		}
	}
}
