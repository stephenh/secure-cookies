package com.bizo.securecookies;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.iharder.Base64;

import com.domainlanguage.time.TimeSource;

/**
 * Given a {@link SecureCookier}, EncryptingCookier encrypts the payload and then delegates to SecureCookier for signing
 * 
 * It only implements the getIfGood method in order to prevent ever running decryption if the signature is invalid in 
 * order to avoid leaking any information about the encryption secret.
 * 
 * Note that this class is meant to be instantiated once and reused across many requests.
 */
public class EncryptingCookier {

  private final SecureCookier delegate;
  private final byte[] encryptionSecret;

  public EncryptingCookier(
    final String base64Encoded256BitAESKey,
    final String base64EncodedHmacSecret,
    final Cookier delegate,
    final TimeSource clock,
    final long duration,
    final TimeUnit durationUnit) {
    this(base64Encoded256BitAESKey, new SecureCookier(delegate, clock, base64EncodedHmacSecret, duration, durationUnit));
  }

  public EncryptingCookier(final String base64Encoded256BitAESKey, final SecureCookier delegate) {
    try {
      encryptionSecret = Base64.decode(base64Encoded256BitAESKey);
    } catch (final IOException e) {
      throw new RuntimeException(e);
    }
    if (encryptionSecret.length != 32) {
      throw new IllegalArgumentException("base64Encoded256BitAESKey must contain a 256 bit key");
    }
    this.delegate = delegate;
  }

  public String getIfGood(final HttpServletRequest req) {
    final String ciphertextBase64 = delegate.getIfGood(req);
    if (ciphertextBase64 == null) {
      return null;
    }
    return decryptFromBase64(ciphertextBase64, encryptionSecret);
  }

  /** Sets {@code value} for {@code res}, appending the expiration time and an HMAC. */
  public void set(final HttpServletResponse res, final String value) {
    final String ciphertextBase64 = encryptToBase64(value, encryptionSecret);
    delegate.set(res, ciphertextBase64);
  }

  /** Unsets the cookie for {@code res} (sends maxAge=0). */
  public void unset(final HttpServletResponse res) {
    delegate.unset(res);
  }

  /**
   * public so tests can encrypt value 
   */
  public static String encryptToBase64(final String value, final byte[] secret) {
    return Base64.encodeBytes(encrypt(value.getBytes(), secret));
  }

  /**
   * public so tests can decrypt value
   */
  public static String decryptFromBase64(final String value, final byte[] secret) {
    try {
      return new String(decrypt(Base64.decode(value), secret));
    } catch (final IOException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * @return byte array containing the concatenation of iv and ciphertext 
   */
  private static byte[] encrypt(final byte[] data, final byte[] key) {
    try {
      final Cipher cipher;
      cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      final SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
      cipher.init(Cipher.ENCRYPT_MODE, keySpec);

      final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      final byte[] iv = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
      outputStream.write(iv);
      outputStream.write(cipher.doFinal(data));
      return outputStream.toByteArray();
    } catch (final RuntimeException e) {
      throw e;
    } catch (final Exception e) {
      throw new RuntimeException(e);
    }
  }

  private static byte[] decrypt(final byte[] data, final byte[] key) {
    try {
      final Cipher cipher;
      cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      final SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
      final IvParameterSpec ivSpec = new IvParameterSpec(data, 0, 16);

      cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

      final byte[] plaintext = cipher.doFinal(data, 16, data.length - 16);
      return plaintext;
    } catch (final RuntimeException e) {
      throw e;
    } catch (final Exception e) {
      throw new RuntimeException(e);
    }
  }
}
