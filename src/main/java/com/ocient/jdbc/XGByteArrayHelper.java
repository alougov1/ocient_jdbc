package com.ocient.jdbc;

// Just a utility for converting byte array to hex string. This is used in multiple places.
public class XGByteArrayHelper {

    public static String bytesToHex(final byte[] bytes){
        final char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++)
		{
			final int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);        
    }

	private static final char[] hexArray = "0123456789abcdef".toCharArray();
}
