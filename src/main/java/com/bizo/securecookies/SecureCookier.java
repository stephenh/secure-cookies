package com.bizo.securecookies;

import com.domainlanguage.time.*;
import java.security.*;
import java.util.concurrent.TimeUnit;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.servlet.http.*;
import net.iharder.*;

/**
 * Applies expiration and HMAC validation to cookies (e.g. for auth/SSO).
 * 
 * Given a regular {@link Cookier} delegate, SecureCookier takes a clock, server secret, and duration that the cookie
 * should be considered valid.
 * 
 * You can then get/set cookie values, and check isExpired/isForged, as needed.
 * 
 * The HMAC logic in {@link #signToBase64(String, String)} is based on:
 * 
 * http://www.cse.msu.edu/~alexliu/publications/Cookie/cookie.pdf
 * 
 * Note that this class is meant to be instantiated once and reused across many requests.
 */
public class SecureCookier {

  private final Cookier delegate;
  private final String secret;
  private final TimeSource clock;
  private final long durationInMillis;

  public SecureCookier(final Cookier delegate, final TimeSource clock, final String secret, final long duration, final TimeUnit durationUnit) {
    this.delegate = delegate;
    this.clock = clock;
    this.secret = secret;
    durationInMillis = durationUnit.toMillis(duration);
  }

  /** @return the data part of the cookie for {@code req}, **even if it is expired or forged**, or {@code null} if unset */
  public String get(final HttpServletRequest req) {
    return getResult(req).data;
  }

  public String getIfGood(final HttpServletRequest req) {
    final DecodeResult result = getResult(req);
    return (!result.expired && !result.forged) ? result.data : null;
  }

  /** @return whether the cookie has expired according to its HMAC'd expiration time */
  public boolean isExpired(final HttpServletRequest req) {
    return getResult(req).expired;
  }

  /** @return whether the cookie failed the HMAC verification */
  public boolean isForged(final HttpServletRequest req) {
    return getResult(req).forged;
  }

  /** Sets {@code value} for {@code res}, appending the expiration time and an HMAC. */
  public void set(final HttpServletResponse res, final String value) {
    final String time = Long.toString(clock.now().asJavaUtilDate().getTime() + durationInMillis);
    final String signed = signToBase64(time, value);
    delegate.set(res, value + "|" + time + "|" + signed);
  }

  /** Unsets the cookie for {@code res} (sends maxAge=0). */
  public void unset(final HttpServletResponse res) {
    delegate.unset(res);
  }

  /** @return the DecodeResult for {@code req}, caching it in the {@code req} attributes */
  private DecodeResult getResult(final HttpServletRequest req) {
    final String key = toString(); // should be SecureCookier@whatever, e.g. unique to this instance
    DecodeResult result = (DecodeResult) req.getAttribute(key);
    if (result == null) {
      result = decode(delegate.get(req));
      req.setAttribute(key, result);
    }
    return result;
  }

  /** Decodes the cookie value, checking the expiration date and HMAC. */
  private DecodeResult decode(final String cookieValue) {
    if (cookieValue == null) {
      return new DecodeResult(null, false, false);
    }

    final int lastBar = cookieValue.lastIndexOf("|");
    final int lastBar2 = cookieValue.lastIndexOf("|", lastBar - 1);
    if (lastBar == -1 || lastBar2 == -1) {
      return new DecodeResult(null, false, true); // treat as forged
    }

    final String data = cookieValue.substring(0, lastBar2);
    final String time = cookieValue.substring(lastBar2 + 1, lastBar);
    final String hmac = cookieValue.substring(lastBar + 1);

    if (hasPast(time)) {
      return new DecodeResult(data, true, false);
    }

    final String expectedHmac = signToBase64(time, data);
    final boolean forged = !hmac.equals(expectedHmac);
    return new DecodeResult(data, false, forged);
  }

  private String signToBase64(final String time, final String data) {
    return signToBase64(secret, time, data);
  }

  private boolean hasPast(final String time) {
    try {
      final Long expired = Long.parseLong(time);
      return clock.now().asJavaUtilDate().getTime() >= expired.longValue();
    } catch (final Exception e) {
      return true; // invalid time component
    }
  }

  /** Public so that tests can set cookies with the signed values. */
  public static String signToBase64(final String secret, final String time, final String data) {
    // We hash the user's expiration time with our secret
    final byte[] k = hmac(time.getBytes(), secret.getBytes());
    // and use that as the key to hash the real time+data payload.
    final byte[] value = hmac((time + data).getBytes(), k);
    // Supposedly using the per-user k is more secure than using the same secret for everyone.
    return Base64.encodeBytes(value);
  }

  /** @return {@code data} HmacSHA1'd with {@code key} */
  private static byte[] hmac(final byte[] data, final byte[] key) {
    try {
      final Mac mac = Mac.getInstance("HmacSHA1");
      final SecretKeySpec secret = new SecretKeySpec(key, "HmacSHA1");
      mac.init(secret);
      return mac.doFinal(data);
    } catch (final InvalidKeyException e) {
      throw new RuntimeException(e);
    } catch (final NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  /** A simple DTO for caching the result of decode. */
  private static final class DecodeResult {
    public final String data;
    public final boolean expired;
    public final boolean forged;

    public DecodeResult(final String data, final boolean expired, final boolean forged) {
      this.data = data;
      this.expired = expired;
      this.forged = forged;
    }
  }

}
