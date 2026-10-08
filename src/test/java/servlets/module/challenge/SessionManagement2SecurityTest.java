package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javax.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;

class SessionManagement2SecurityTest {

  @Test
  void tokenBelongsToOneSession() {
    HttpSession session = TestSession.create();
    String token = SessionManagement2Security.issueActionToken(session);

    assertTrue(SessionManagement2Security.hasActionToken(session, token));
    assertFalse(SessionManagement2Security.hasActionToken(session, "invalid"));
    assertFalse(SessionManagement2Security.hasActionToken(TestSession.create(), token));
  }

  @Test
  void passwordChangeRequiresAuthenticatedSubapplicationOwner() {
    HttpSession session = TestSession.create();
    session.setAttribute("userName", "admin");
    session.setAttribute("userRole", "admin");
    String token = SessionManagement2Security.issueActionToken(session);

    assertFalse(
        SessionManagement2Security.mayChangeChallenge2Password(
            session, "owner@example.test", token));
    SessionManagement2Security.recordSubUser(session, "owner@example.test");
    assertTrue(
        SessionManagement2Security.mayChangeChallenge2Password(
            session, "owner@example.test", token));
    assertFalse(
        SessionManagement2Security.mayChangeChallenge2Password(
            session, "other@example.test", token));
    SessionManagement2Security.clearSubUser(session);
    assertFalse(
        SessionManagement2Security.mayChangeChallenge2Password(
            session, "owner@example.test", token));
  }
}
