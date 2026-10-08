package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class SessionManagementCookieTest {

  @Test
  void forgedRoleCookieDoesNotGrantAdminResult() throws Exception {
    HttpSession session = playerSession();
    HttpServletRequest request = request(session);
    when(request.getCookies())
        .thenReturn(new Cookie[] {new Cookie("checksum", encode("userRole=administrator"))});
    when(request.getParameter("adminDetected")).thenReturn("false");
    when(request.getParameter("returnPassword")).thenReturn("false");
    when(request.getParameter("upgradeUserToAdmin")).thenReturn("false");
    StringWriter body = new StringWriter();
    HttpServletResponse response = response(body);

    new SessionManagement1().doPost(request, response);

    assertFalse(body.toString().contains("Admin Only Club"));
  }

  @Test
  void forgedSubSessionCookieDoesNotGrantAdminResult() throws Exception {
    HttpSession session = playerSession();
    HttpServletRequest request = request(session);
    when(request.getCookies())
        .thenReturn(new Cookie[] {new Cookie("SubSessionID", encode(encode("0000000000000009")))});
    when(request.getParameter("useSecurity")).thenReturn("true");
    when(request.getParameter("userId")).thenReturn("0000000000000001");
    StringWriter body = new StringWriter();
    HttpServletResponse response = response(body);

    new SessionManagement4().doPost(request, response);

    assertFalse(body.toString().contains("Admin Only Club"));
  }

  @Test
  void platformAdminNeedsItsOwnSessionBoundChallengeOneCookie() throws Exception {
    HttpSession session = playerSession();
    session.setAttribute("userRole", "admin");
    HttpServletRequest request = request(session);
    when(request.getCookies())
        .thenReturn(new Cookie[] {new Cookie("checksum", encode("userRole=administrator"))});
    StringWriter body = new StringWriter();

    new SessionManagement1().doPost(request, response(body));
    assertFalse(body.toString().contains("Admin Only Club"));

    HttpServletResponse pageResponse = mock(HttpServletResponse.class);
    SessionChallengeSecurity.issueChallengeCookie(
        session, request, pageResponse, "challenge1", "checksum");
    ArgumentCaptor<Cookie> cookie = ArgumentCaptor.forClass(Cookie.class);
    verify(pageResponse).addCookie(cookie.capture());
    assertTrue(cookie.getValue().isHttpOnly());
    assertTrue(cookie.getValue().getSecure());
    assertTrue("/challenges".equals(cookie.getValue().getPath()));
    when(request.getCookies())
        .thenReturn(new Cookie[] {new Cookie("checksum", encode("userRole=administrator"))});
    body = new StringWriter();
    new SessionManagement1().doPost(request, response(body));
    assertFalse(body.toString().contains("Admin Only Club"));
    when(request.getCookies()).thenReturn(new Cookie[] {cookie.getValue()});
    body = new StringWriter();
    new SessionManagement1().doPost(request, response(body));
    assertTrue(body.toString().contains("Admin Only Club"));
  }

  @Test
  void challengeFourCookieIsBoundToTheOriginalSession() throws Exception {
    HttpSession adminSession = playerSession();
    adminSession.setAttribute("userRole", "admin");
    HttpServletRequest adminRequest = request(adminSession);
    HttpServletResponse pageResponse = mock(HttpServletResponse.class);
    SessionChallengeSecurity.issueChallengeCookie(
        adminSession, adminRequest, pageResponse, "challenge4", "SubSessionID");
    ArgumentCaptor<Cookie> cookie = ArgumentCaptor.forClass(Cookie.class);
    verify(pageResponse).addCookie(cookie.capture());
    when(adminRequest.getCookies()).thenReturn(new Cookie[] {cookie.getValue()});
    StringWriter body = new StringWriter();
    new SessionManagement4().doPost(adminRequest, response(body));
    assertTrue(body.toString().contains("Admin Only Club"));

    HttpSession anotherSession = playerSession();
    anotherSession.setAttribute("userRole", "admin");
    HttpServletRequest anotherRequest = request(anotherSession);
    when(anotherRequest.getCookies()).thenReturn(new Cookie[] {cookie.getValue()});
    body = new StringWriter();
    new SessionManagement4().doPost(anotherRequest, response(body));
    assertFalse(body.toString().contains("Admin Only Club"));

    adminSession.setAttribute("userRole", "player");
    when(adminRequest.getCookies()).thenReturn(new Cookie[] {cookie.getValue()});
    body = new StringWriter();
    new SessionManagement4().doPost(adminRequest, response(body));
    assertFalse(body.toString().contains("Admin Only Club"));
  }

  private static HttpSession playerSession() {
    HttpSession session = TestSession.create();
    session.setAttribute("userRole", "player");
    session.setAttribute("userName", "ctf-player");
    return session;
  }

  private static HttpServletRequest request(HttpSession session) {
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getSession()).thenReturn(session);
    when(request.getSession(true)).thenReturn(session);
    when(request.getRemoteAddr()).thenReturn("127.0.0.1");
    when(request.getContextPath()).thenReturn("");
    when(request.isSecure()).thenReturn(true);
    return request;
  }

  private static HttpServletResponse response(StringWriter body) throws Exception {
    HttpServletResponse response = mock(HttpServletResponse.class);
    when(response.getWriter()).thenReturn(new PrintWriter(body));
    return response;
  }

  private static String encode(String value) {
    return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
  }
}
