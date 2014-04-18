package com.bizo.securecookies;

import javax.crypto.KeyGenerator;

import net.iharder.Base64;

public class KeyGen {

  public static void main(final String[] args) throws Exception {
    final KeyGenerator aes = KeyGenerator.getInstance("AES");
    aes.init(256);
    System.out.println("AES 256 bit key: " + Base64.encodeBytes(aes.generateKey().getEncoded()));
    final KeyGenerator hmacSha256 = KeyGenerator.getInstance("HmacSHA256");
    hmacSha256.init(256);
    System.out.println("HmacSha256 256 bit key: " + Base64.encodeBytes(aes.generateKey().getEncoded()));
  }
}
