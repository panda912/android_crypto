package com.panda912.crypto.mbedtls;

import android.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by panda on 2021/4/27 13:16
 */
public class Crypto {
  public static final int ZERO_PADDING = 0;
  public static final int PKCS1_PADDING = 1;
  public static final int PKCS7_PADDING = 2;
  public static final int ISO10126_PADDING = 3;

  static {
    try {
      System.loadLibrary("crypto");
    } catch (Throwable th) {
      th.printStackTrace();
    }
  }

  public static String aesEncrypt(String content) throws Throwable {
//    IvParameterSpec iv = new IvParameterSpec("1234567890123456".getBytes());
    SecretKeySpec key = new SecretKeySpec("1234567890123456".getBytes(), "AES");
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding");
    cipher.init(Cipher.ENCRYPT_MODE, key);
    byte[] output = cipher.doFinal(content.getBytes());
    return Base64.encodeToString(output, Base64.DEFAULT);
  }

  public static String aesDecrypt(byte[] content) throws Throwable {
    IvParameterSpec iv = new IvParameterSpec("1234567890123456".getBytes());
    SecretKeySpec key = new SecretKeySpec("1234567890123456".getBytes(), "AES");
    Cipher cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");
    cipher.init(Cipher.DECRYPT_MODE, key, iv);
    byte[] output = cipher.doFinal(content);
    return new String(output);
  }


  public static native byte[] aesEncrypt(String plainText, String key);

  public static native String aesDecrypt(byte[] cipher, String key);

  public static native byte[] aesEncrypt(String plainText, String key, String iv);

  public static native String aesDecrypt(byte[] cipher, String key, String iv);

  public static native byte[] desEncrypt(String plainText, String key);

  public static native String desDecrypt(byte[] cipher, String key);

  public static native byte[] desEncrypt(String plainText, String key, String iv);

  public static native String desDecrypt(byte[] cipher, String key, String iv);

}
