package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;
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
