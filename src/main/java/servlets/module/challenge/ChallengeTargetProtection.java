package servlets.module.challenge;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.servlet.http.HttpSession;

/** Server-side authorization for the CSRF challenge target actions. */
public final class ChallengeTargetProtection {

  private static final String NONCE_ATTRIBUTE = "csrfChallengeTargetNonce";
  private static final SecureRandom RANDOM = new SecureRandom();

  private ChallengeTargetProtection() {}

  /**
   * Returns the token for the current session, creating it when the challenge page is first opened.
   */
  public static String issueToken(HttpSession session) {
    synchronized (session) {
      Object existing = session.getAttribute(NONCE_ATTRIBUTE);
      if (existing instanceof String && !((String) existing).isEmpty()) {
        return (String) existing;
      }
      byte[] randomBytes = new byte[32];
      RANDOM.nextBytes(randomBytes);
      String token = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
      session.setAttribute(NONCE_ATTRIBUTE, token);
      return token;
    }
  }

  /** A target request may only change the current user's own progress with their session token. */
  public static boolean isAuthorized(
      HttpSession session, String targetUserId, String submittedToken) {
    if (session == null || targetUserId == null || submittedToken == null) {
      return false;
    }
    Object userId = session.getAttribute("userStamp");
    Object token = session.getAttribute(NONCE_ATTRIBUTE);
    if (!(userId instanceof String)
        || !(token instanceof String)
        || !targetUserId.equals(userId)
        || ((String) token).isEmpty()) {
      return false;
    }
    return MessageDigest.isEqual(
        ((String) token).getBytes(StandardCharsets.UTF_8),
        submittedToken.getBytes(StandardCharsets.UTF_8));
  }
}
