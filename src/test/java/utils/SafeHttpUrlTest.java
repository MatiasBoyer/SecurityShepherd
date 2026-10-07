package utils;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class SafeHttpUrlTest {

  private static final String FALLBACK = "https://example.org/help";

  @Test
  void preservesValidHttpAndHttpsUrls() {
    assertEquals(
        "http://example.com/path", SafeHttpUrl.validate("http://example.com/path", FALLBACK));
    assertEquals(
        "https://example.com/?a=1&b=2",
        SafeHttpUrl.validate("https://example.com/?a=1&b=2", FALLBACK));
  }

  @Test
  void rejectsExecutableOrMalformedUrls() {
    assertEquals(FALLBACK, SafeHttpUrl.validate("javascript:alert(1)", FALLBACK));
    assertEquals(FALLBACK, SafeHttpUrl.validate("data:text/html,<script>", FALLBACK));
    assertEquals(
        FALLBACK, SafeHttpUrl.validate("https://example.com/\" onload=\"alert(1)", FALLBACK));
    assertEquals(FALLBACK, SafeHttpUrl.validate("//example.com", FALLBACK));
    assertEquals(FALLBACK, SafeHttpUrl.validate("https://user:pass@example.com/", FALLBACK));
  }
}
