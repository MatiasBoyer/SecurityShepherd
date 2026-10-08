package servlets.module.challenge;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;

class SessionManagement2ChangePasswordTest {

  @Test
  void unauthenticatedResetIsForbidden() throws Exception {
    HttpSession session = TestSession.create();
    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);
    when(request.getSession()).thenReturn(session);
    when(request.getSession(true)).thenReturn(session);
    when(request.getRemoteAddr()).thenReturn("127.0.0.1");
    when(response.getWriter()).thenReturn(new PrintWriter(new StringWriter()));

    new SessionManagement2ChangePassword().doPost(request, response);

    verify(response).sendError(HttpServletResponse.SC_FORBIDDEN);
  }

  @Test
  void unauthenticatedLoginIsForbidden() throws Exception {
    HttpSession session = TestSession.create();
    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpServletResponse response = mock(HttpServletResponse.class);
    when(request.getSession()).thenReturn(session);
    when(request.getSession(true)).thenReturn(session);
    when(request.getRemoteAddr()).thenReturn("127.0.0.1");

    new SessionManagement2().doPost(request, response);

    verify(response).sendError(HttpServletResponse.SC_FORBIDDEN);
  }
}
