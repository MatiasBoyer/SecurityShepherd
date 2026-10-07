package servlets.module.challenge;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;

class DirectObjectBankAuthorizationTest {

  @Test
  void balanceRequestCannotReadAnotherAccount() throws Exception {
    HttpServletRequest request = authenticatedBankRequest();
    HttpServletResponse response = mock(HttpServletResponse.class);
    when(request.getParameter("accountNumber")).thenReturn("456");

    new DirectObjectBankCurrentBalance().doPost(request, response);

    verify(response).sendError(HttpServletResponse.SC_FORBIDDEN);
    verify(response, never()).getWriter();
  }

  @Test
  void transferRequestCannotDebitAnotherAccount() throws Exception {
    HttpServletRequest request = authenticatedBankRequest();
    HttpServletResponse response = mock(HttpServletResponse.class);
    when(request.getParameter("senderAccountNumber")).thenReturn("456");

    new DirectObjectBankTransfer().doPost(request, response);

    verify(response).sendError(HttpServletResponse.SC_FORBIDDEN);
    verify(response, never()).getWriter();
  }

  private static HttpServletRequest authenticatedBankRequest() {
    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpSession session = mock(HttpSession.class);
    when(request.getSession(true)).thenReturn(session);
    when(request.getSession()).thenReturn(session);
    when(request.getRemoteAddr()).thenReturn("127.0.0.1");
    when(session.getAttribute("userRole")).thenReturn("player");
    when(session.getAttribute("userName")).thenReturn("player-one");
    when(session.getAttribute("directObjectBankAccount")).thenReturn("123");
    return request;
  }
}
