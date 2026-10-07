package utils;

import java.net.URI;
import java.net.URISyntaxException;

/** Validates links before they are placed in an HTML href attribute. */
public final class SafeHttpUrl {

  private SafeHttpUrl() {}

  public static String validate(String candidate, String fallback) {
    if (candidate == null) {
      return fallback;
    }
    try {
      URI uri = new URI(candidate);
      String scheme = uri.getScheme();
      if (scheme == null
          || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))
          || uri.getHost() == null
          || uri.getHost().isEmpty()
          || uri.getRawUserInfo() != null
          || uri.getPort() > 65535) {
        return fallback;
      }
      return uri.toASCIIString();
    } catch (URISyntaxException e) {
      return fallback;
    }
  }
}
