package com.bizo.securecookies;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import org.junit.Before;
import org.junit.Test;

import net.iharder.Base64;

public class EncryptingCookierTest {

  private byte[] encryptionSecret;

  @Before
  public void setUp() throws Exception {
    encryptionSecret = Base64.decode("YJIwQKY7/6DttK/7152MhOVdANIQsDIZCr0dvn/z/DQ=");
  }

  @Test
  public void encrypt() throws Exception {
    final String testValue = "this is my test message";
    final String ciphertext = EncryptingCookier.encryptToBase64(testValue, encryptionSecret);
    final String plaintext = EncryptingCookier.decryptFromBase64(ciphertext, encryptionSecret);
    assertThat(plaintext, is(testValue));
  }
}
