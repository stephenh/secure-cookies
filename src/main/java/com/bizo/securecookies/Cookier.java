package com.bizo.securecookies;

import static java.util.concurrent.TimeUnit.*;

import java.util.concurrent.*;
import javax.servlet.http.*;

/**
 * Wraps functionality for getting/settings cookies.
 * 
 * Typically you would instantiate 1 instance of this class in your stateless service, and then reuse the instance for
 * all of the requests--e.g. get/set take requests and responses as parameters.
 * 
 * All cookies set have path=/.
 */
public class Cookier {

  private final String name;
  private final int maxAge;
  private final String domain;
  private boolean secure;

  /** A cookie named {@code name} that is a session cookie. */
  public Cookier(final String name) {
    this(name, -1, SECONDS);
  }

  /** A cookie named {@code name} that is a session cookie for {@code domain}. */
  public Cookier(final String name, final String domain) {
    this(name, -1, SECONDS, domain);
  }

  /** A cookie named {@code name} that expires in {@code maxAge}. */
  public Cookier(final String name, final long maxAge, final TimeUnit maxAgeUnit) {
    this(name, maxAge, maxAgeUnit, null);
  }

  /** A cookie named {@code name} that expires in {@code maxAge} (use -1 for session) for {@code domain}. */
  public Cookier(final String name, final long maxAge, final TimeUnit maxAgeUnit, final String domain) {
    this.name = name;
    this.maxAge = (int) maxAgeUnit.toSeconds(maxAge);
    this.domain = domain;
  }

  /** Sets {@code value} into {@code res} for the configured age/domain/path. */
  public void set(final HttpServletResponse res, final String value) {
    final Cookie cookie = new Cookie(name, value);
    cookie.setMaxAge(maxAge);
    if (domain != null) {
      cookie.setDomain(domain);
    }
    cookie.setSecure(secure);
    cookie.setPath("/");
    res.addCookie(cookie);
  }

  /** Expires the cookie for {@code res} (sends maxAge=0). */
  public void unset(final HttpServletResponse res) {
    final Cookie cookie = new Cookie(name, "");
    cookie.setMaxAge(0);
    if (domain != null) {
      cookie.setDomain(domain);
    }
    cookie.setSecure(secure);
    cookie.setPath("/");
    res.addCookie(cookie);
  }

  /** @return the value for {@code req} for {@code null} if unset */
  public String get(final HttpServletRequest req) {
    final Cookie c = getCookieOrNull(req);
    if (c == null) {
      return null;
    }
    return c.getValue();
  }

  public void setSecure(boolean secure) {
    this.secure = secure;
  }

  private Cookie getCookieOrNull(final HttpServletRequest req) {
    if (req.getCookies() != null) {
      for (final Cookie cookie : req.getCookies()) {
        if (cookie.getName().equals(name)) {
          return cookie;
        }
      }
    }
    return null;
  }

}
