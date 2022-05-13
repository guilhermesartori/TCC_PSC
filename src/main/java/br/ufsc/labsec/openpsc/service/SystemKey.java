package br.ufsc.labsec.openpsc.service;

import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;

import org.bouncycastle.util.Arrays;

public class SystemKey {

  public static final String SYSTEM_KEY_ALGORITHM = "AES";

  private static byte[] KEY;
  private static byte[] IV;
  private static KeyGenerator keyGenerator;

  static {
    try {
      keyGenerator = KeyGenerator.getInstance(SYSTEM_KEY_ALGORITHM);
      keyGenerator.init(256);
    } catch (NoSuchAlgorithmException e) {
      // should never happen
    }
  }

  public static byte[] getKey() {
    if (KEY == null)
      refreshKey();
    return KEY;
  }

  public static byte[] getIv() {
    if (KEY == null)
      refreshKey();
    return IV;
  }

  public static void refreshKey() {
    KEY = keyGenerator.generateKey().getEncoded();
    IV = Arrays.copyOf(KEY, 16);
  }

}
