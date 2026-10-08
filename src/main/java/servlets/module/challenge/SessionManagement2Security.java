package servlets.module.challenge;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.servlet.http.HttpSession;

/** Server-held subapplication identity and action token for Session Management Challenge Two. */
public final class SessionManagement2Security {

  private static final String SUBUSER = "authenticatedChallengeUser:challenge2";
  private static final String ACTION_TOKEN = "sessionManagement2ActionToken";
  private static final SecureRandom RANDOM = new SecureRandom();

  private SessionManagement2Security() {}

  static void recordSubUser(HttpSession session, String email) {
    session.setAttribute(SUBUSER, email);
  }

  static void clearSubUser(HttpSession session) {
    session.removeAttribute(SUBUSER);
  }

  static boolean mayChangeChallenge2Password(HttpSession session, String email, String token) {
    return email != null
        && !email.isEmpty()
        && hasActionToken(session, token)
        && email.equals(session.getAttribute(SUBUSER));
  }

  public static String issueActionToken(HttpSession session) {
    synchronized (session) {
      Object existing = session.getAttribute(ACTION_TOKEN);
      if (existing instanceof String && !((String) existing).isEmpty()) {
        return (String) existing;
      }
      byte[] randomBytes = new byte[32];
      RANDOM.nextBytes(randomBytes);
      String token = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
      session.setAttribute(ACTION_TOKEN, token);
      return token;
    }
  }

  static boolean hasActionToken(HttpSession session, String submittedToken) {
    if (session == null || submittedToken == null) {
      return false;
    }
    Object token = session.getAttribute(ACTION_TOKEN);
    return token instanceof String
        && !((String) token).isEmpty()
        && MessageDigest.isEqual(
            ((String) token).getBytes(StandardCharsets.UTF_8),
            submittedToken.getBytes(StandardCharsets.UTF_8));
  }
}
