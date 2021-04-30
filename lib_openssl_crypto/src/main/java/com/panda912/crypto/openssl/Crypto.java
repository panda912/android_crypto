package com.panda912.crypto.openssl;

/**
 * Created by panda on 2021/4/25 11:22
 */
public class Crypto {

  static {
    try {
      System.loadLibrary("crypto");
    } catch (Throwable th) {
      th.printStackTrace();
    }
  }

  /**
   * AES_256_cbc encryption
   *
   * @param plainText plain text
   * @param key       key
   * @param iv        iv
   * @param mode      mode
   * @param padding   padding
   * @return bytes
   */
  public static native byte[] aesEncrypt(String plainText, String key, String iv, int mode, int padding);

  /**
   * AES_256_cbc decryption
   *
   * @param buffer  cipher bytes
   * @param key     key
   * @param iv      iv
   * @param mode    mode
   * @param padding padding
   * @return plain text
   */
  public static native String aesDecrypt(byte[] buffer, String key, String iv, int mode, int padding);
}
