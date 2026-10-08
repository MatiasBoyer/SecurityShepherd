package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;

class SessionManagementAuthorizationTest {

  @Test
  void sixthChallengeAcceptsAnAnswerOnlyForTheSignedInAccount() {
    HttpSession session = mock(HttpSession.class);
    when(session.getAttribute("sessionManagementSixAuthenticatedUser")).thenReturn("manager");

    assertTrue(SessionManagement6SecretQuestion.canUseAnswer(session, "manager"));
    assertFalse(SessionManagement6SecretQuestion.canUseAnswer(session, "administrator"));
    assertFalse(SessionManagement6SecretQuestion.canUseAnswer(session, null));
  }

  @Test
  void seventhChallengeAcceptsAnAnswerOnlyForTheSignedInAccount() {
    HttpSession session = mock(HttpSession.class);
    when(session.getAttribute("sessionManagementSevenAuthenticatedUser")).thenReturn("manager");

    assertTrue(SessionManagement7SecretQuestion.canUseAnswer(session, "manager"));
    assertFalse(SessionManagement7SecretQuestion.canUseAnswer(session, "administrator"));
    assertFalse(SessionManagement7SecretQuestion.canUseAnswer(session, null));
  }

  @Test
  void eighthChallengeDoesNotAcceptACookieAsAuthority() {
    HttpSession session = mock(HttpSession.class);
    when(session.getAttribute("userRole")).thenReturn("admin");
    when(session.getAttribute("sessionManagementEightRole")).thenReturn(null, "superuser");

    assertFalse(SessionManagement8.canAccessPrivilegedView(session));
    assertTrue(SessionManagement8.canAccessPrivilegedView(session));
  }

  @Test
  void forgedPrivilegedCookieStillGetsNormalPlayerResponse() throws Exception {
    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);
    HttpSession session = mock(HttpSession.class);
    StringWriter body = new StringWriter();
    PrintWriter writer = new PrintWriter(body);
    when(request.getSession()).thenReturn(session);
    when(request.getSession(true)).thenReturn(session);
    when(request.getRemoteAddr()).thenReturn("127.0.0.1");
    when(request.getCookies())
        .thenReturn(new Cookie[] {new Cookie("challengeRole", "nmHqLjQknlHs")});
    when(request.getParameter("returnUserRole")).thenReturn("false");
    when(request.getParameter("returnPassword")).thenReturn("false");
    when(request.getParameter("adminDetected")).thenReturn("false");
    when(response.getWriter()).thenReturn(writer);
    when(session.getAttribute("userRole")).thenReturn("admin");
    when(session.getAttribute("userName")).thenReturn("player-one");

    new SessionManagement8().doPost(request, response);
    writer.flush();

    assertTrue(body.toString().contains("not a privileged User"));
    assertFalse(body.toString().contains("Your result key"));
  }
}
