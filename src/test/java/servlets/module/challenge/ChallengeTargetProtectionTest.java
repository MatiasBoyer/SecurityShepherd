package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;

class ChallengeTargetProtectionTest {

  @Test
  void firstChallengeCannotMutateProgressViaGet() throws Exception {
    HttpServletResponse response = mock(HttpServletResponse.class);

    new CsrfChallengeTargetOne().doGet(mock(HttpServletRequest.class), response);

    verify(response).sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
  }

  @Test
  void csrfTargetRejectsMissingAndGuessedTokens() {
    HttpSession session = mock(HttpSession.class);
    when(session.getAttribute("userStamp")).thenReturn("victim");

    assertFalse(ChallengeTargetProtection.isAuthorized(session, "victim", null));
    assertFalse(ChallengeTargetProtection.isAuthorized(session, "victim", "guessed"));
  }

  @Test
  void csrfTargetCannotIncrementAnotherUsersCounter() {
    HttpSession session = mock(HttpSession.class);
    when(session.getAttribute("userStamp")).thenReturn("victim");
    when(session.getAttribute("csrfChallengeTargetNonce")).thenReturn("valid-token");

    assertFalse(ChallengeTargetProtection.isAuthorized(session, "attacker", "valid-token"));
    assertTrue(ChallengeTargetProtection.isAuthorized(session, "victim", "valid-token"));
  }

  @Test
  void fourthChallengeRequiresVictimsSessionNonce() {
    HttpSession session = mock(HttpSession.class);
    when(session.getAttribute("userStamp")).thenReturn("victim");
    when(session.getAttribute("csrfChallengeTargetNonce")).thenReturn("victim-token");

    assertFalse(ChallengeTargetProtection.isAuthorized(session, "victim", "attacker-token"));
    assertTrue(ChallengeTargetProtection.isAuthorized(session, "victim", "victim-token"));
  }

  @Test
  void csrfTargetUsesDifferentTokensForDifferentSessions() {
    HttpSession first = TestSession.create();
    HttpSession second = TestSession.create();

    assertNotEquals(
        ChallengeTargetProtection.issueToken(first), ChallengeTargetProtection.issueToken(second));
  }
}
