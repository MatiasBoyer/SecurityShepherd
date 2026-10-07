package servlets.module.challenge;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.servlet.http.HttpSession;

/** Server-held identities and reset grants for the session management challenges. */
public final class SessionChallengeSecurity {

  private static final String SUBUSER_PREFIX = "authenticatedChallengeUser:";
  private static final String RESET_GRANT = "sessionManagement5ResetGrant";
  private static final String ACTION_TOKEN = "sessionManagementActionToken";
  private static final long RESET_LIFETIME_MILLIS = 10L * 60L * 1000L;
  private static final SecureRandom RANDOM = new SecureRandom();

  private SessionChallengeSecurity() {}

  static boolean isPlatformAdmin(HttpSession session) {
    return session != null && "admin".equals(session.getAttribute("userRole"));
  }

  static void recordSubUser(HttpSession session, String challenge, String userName) {
    session.setAttribute(SUBUSER_PREFIX + challenge, userName);
  }

  static void clearSubUser(HttpSession session, String challenge) {
    session.removeAttribute(SUBUSER_PREFIX + challenge);
  }

  static boolean isSubUser(HttpSession session, String challenge, String userName) {
    return session != null
        && userName != null
        && !userName.isEmpty()
        && userName.equals(session.getAttribute(SUBUSER_PREFIX + challenge));
  }

  static boolean mayChangeChallenge2Password(HttpSession session, String email, String token) {
    return email != null
        && !email.isEmpty()
        && hasActionToken(session, token)
        && (isSubUser(session, "challenge2", email) || isPlatformAdmin(session));
  }

  static String authenticatedSubUser(HttpSession session, String challenge) {
    if (session == null) {
      return null;
    }
    Object userName = session.getAttribute(SUBUSER_PREFIX + challenge);
    return userName instanceof String ? (String) userName : null;
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

  static String issueResetToken(HttpSession session, String userName) {
    byte[] randomBytes = new byte[32];
    RANDOM.nextBytes(randomBytes);
    String token = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    synchronized (session) {
      session.setAttribute(
          RESET_GRANT, new ResetGrant(userName, token, System.currentTimeMillis()));
    }
    return token;
  }

  static boolean consumeResetToken(HttpSession session, String userName, String token) {
    if (session == null || userName == null || token == null) {
      return false;
    }
    synchronized (session) {
      Object candidate = session.getAttribute(RESET_GRANT);
      if (!(candidate instanceof ResetGrant)) {
        return false;
      }
      ResetGrant grant = (ResetGrant) candidate;
      long age = System.currentTimeMillis() - grant.issuedAt;
      if (age < 0 || age > RESET_LIFETIME_MILLIS) {
        session.removeAttribute(RESET_GRANT);
        return false;
      }
      if (!grant.userName.equals(userName)
          || !MessageDigest.isEqual(
              grant.token.getBytes(StandardCharsets.UTF_8),
              token.getBytes(StandardCharsets.UTF_8))) {
        return false;
      }
      session.removeAttribute(RESET_GRANT);
      return true;
    }
  }

  private static final class ResetGrant {
    private final String userName;
    private final String token;
    private final long issuedAt;

    private ResetGrant(String userName, String token, long issuedAt) {
      this.userName = userName;
      this.token = token;
      this.issuedAt = issuedAt;
    }
  }
}
