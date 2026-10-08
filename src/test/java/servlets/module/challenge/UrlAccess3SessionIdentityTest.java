package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;
import java.util.ResourceBundle;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;

class UrlAccess3SessionIdentityTest {

  @Test
  void forgedSuperAdminCookieDoesNotElevatePlatformAdministrator() throws Exception {
    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);
    HttpSession session = mock(HttpSession.class);
    StringWriter responseBody = new StringWriter();
    PrintWriter writer = new PrintWriter(responseBody);
    when(response.getWriter()).thenReturn(writer);
    when(request.getSession()).thenReturn(session);
    when(request.getSession(true)).thenReturn(session);
    when(request.getRemoteAddr()).thenReturn("127.0.0.1");
    when(request.getParameter("userId")).thenReturn("d3d9446802a44259755d38e6d163e820");
    when(request.getParameter("secure")).thenReturn("true");
    when(session.getAttribute("userRole")).thenReturn("admin");
    when(session.getAttribute("userName")).thenReturn("player-one");
    String forgedPerson =
        Base64.getEncoder()
            .encodeToString("MrJohnReillyTheSecond".getBytes(StandardCharsets.UTF_8));
    when(request.getCookies()).thenReturn(new Cookie[] {new Cookie("currentPerson", forgedPerson)});

    new UrlAccess3().doPost(request, response);
    writer.flush();

    String guestHeading =
        ResourceBundle.getBundle(
                "i18n.servlets.challenges.urlAccess.urlAccess3", new Locale("en_GB"))
            .getString("response.notSuperAdmin");
    assertTrue(responseBody.toString().contains(guestHeading));
    verify(session).setAttribute("urlAccessThreeUser", "aGuest");
  }
}
