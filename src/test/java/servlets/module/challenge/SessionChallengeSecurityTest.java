package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javax.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;

class SessionChallengeSecurityTest {

  @Test
  void subuserAuthorizationRequiresServerSideLogin() {
    HttpSession session = TestSession.create();

    assertFalse(SessionChallengeSecurity.isSubUser(session, "challenge3", "admin"));
    SessionChallengeSecurity.recordSubUser(session, "challenge3", "guest");
    assertFalse(SessionChallengeSecurity.isSubUser(session, "challenge3", "admin"));
    assertTrue(SessionChallengeSecurity.isSubUser(session, "challenge3", "guest"));
  }

  @Test
  void resetTokenIsBoundToUserAndSingleUse() {
    HttpSession session = TestSession.create();
    String token = SessionChallengeSecurity.issueResetToken(session, "admin");

    assertFalse(SessionChallengeSecurity.consumeResetToken(session, "other", token));
    assertTrue(SessionChallengeSecurity.consumeResetToken(session, "admin", token));
    assertFalse(SessionChallengeSecurity.consumeResetToken(session, "admin", token));
  }

  @Test
  void clientCookieCannotGrantAdministratorRole() {
    HttpSession session = TestSession.create();
    session.setAttribute("userRole", "player");

    assertFalse(SessionChallengeSecurity.isPlatformAdmin(session));
    session.setAttribute("userRole", "admin");
    assertTrue(SessionChallengeSecurity.isPlatformAdmin(session));
  }

  @Test
  void passwordChangeRequiresSessionActionToken() {
    HttpSession session = TestSession.create();
    String token = SessionChallengeSecurity.issueActionToken(session);

    assertFalse(SessionChallengeSecurity.hasActionToken(session, null));
    assertFalse(SessionChallengeSecurity.hasActionToken(session, "guessed"));
    assertTrue(SessionChallengeSecurity.hasActionToken(session, token));
    assertFalse(SessionChallengeSecurity.hasActionToken(TestSession.create(), token));
  }

  @Test
  void platformAdministratorCannotResetChallenge2AccountWithoutSubuserLogin() {
    HttpSession session = TestSession.create();
    session.setAttribute("userRole", "admin");
    session.setAttribute("userName", "admin");
    String token = SessionChallengeSecurity.issueActionToken(session);

    assertFalse(
        SessionChallengeSecurity.mayChangeChallenge2Password(
            session, "admin@example.test", "wrong"));
    assertFalse(
        SessionChallengeSecurity.mayChangeChallenge2Password(session, "admin@example.test", token));
  }

  @Test
  void playerCannotRecoverAnotherChallenge2Account() {
    HttpSession session = TestSession.create();
    session.setAttribute("userRole", "player");
    String token = SessionChallengeSecurity.issueActionToken(session);

    assertFalse(
        SessionChallengeSecurity.mayChangeChallenge2Password(session, "admin@example.test", token));
    SessionChallengeSecurity.recordSubUser(session, "challenge2", "guest@example.test");
    assertFalse(
        SessionChallengeSecurity.mayChangeChallenge2Password(session, "admin@example.test", token));
    assertTrue(
        SessionChallengeSecurity.mayChangeChallenge2Password(session, "guest@example.test", token));
  }
}
