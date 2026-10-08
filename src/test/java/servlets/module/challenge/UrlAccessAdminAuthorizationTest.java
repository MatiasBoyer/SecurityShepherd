package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;

class UrlAccessAdminAuthorizationTest {

  @Test
  void firstGuestStatusFlowStillWorks() throws Exception {
    HttpServletRequest request = playerRequest();
    HttpServletResponse response = mock(HttpServletResponse.class);
    StringWriter body = new StringWriter();
    PrintWriter writer = new PrintWriter(body);
    when(response.getWriter()).thenReturn(writer);
    when(request.getParameter("userData")).thenReturn("4816283");

    new UrlAccess1().doPost(request, response);
    writer.flush();

    assertTrue(body.toString().contains("<h2 class='title'>"));
    assertFalse(body.toString().contains("<a>"));
  }

  @Test
  void secondGuestInfoFlowStillWorks() throws Exception {
    HttpServletRequest request = playerRequest();
    HttpServletResponse response = mock(HttpServletResponse.class);
    StringWriter body = new StringWriter();
    PrintWriter writer = new PrintWriter(body);
    when(response.getWriter()).thenReturn(writer);
    when(request.getParameter("guestData")).thenReturn("sOdjh318UD8ismcoa98smcj21dmdoaoIS9");

    new UrlAccess2().doPost(request, response);
    writer.flush();

    assertTrue(body.toString().contains("<h2 class='title'>"));
    assertFalse(body.toString().contains("<a>"));
  }

  @Test
  void firstAdminEndpointRejectsPlayerEvenWithExpectedRequestData() throws Exception {
    HttpServletRequest request = playerRequest();
    HttpServletResponse response = mock(HttpServletResponse.class);
    when(request.getParameter("userData")).thenReturn("4816283");

    new UrlAccess1Admin().doPost(request, response);

    verify(response).sendError(HttpServletResponse.SC_FORBIDDEN);
    verify(response, never()).getWriter();
  }

  @Test
  void secondAdminEndpointRejectsPlayerEvenWithExpectedRequestData() throws Exception {
    HttpServletRequest request = playerRequest();
    HttpServletResponse response = mock(HttpServletResponse.class);
    when(request.getParameter("adminData")).thenReturn("youAreAnAdminOfAwesomenessWoopWoop");

    new UrlAccess2Admin().doPost(request, response);

    verify(response).sendError(HttpServletResponse.SC_FORBIDDEN);
    verify(response, never()).getWriter();
  }

  @Test
  void firstAdminEndpointRejectsPlatformAdminWithoutChallengeAuthorization() throws Exception {
    HttpServletRequest request = requestWithRole("admin");
    HttpServletResponse response = mock(HttpServletResponse.class);
    when(request.getParameter("userData")).thenReturn("4816283");

    new UrlAccess1Admin().doPost(request, response);

    verify(response).sendError(HttpServletResponse.SC_FORBIDDEN);
    verify(response, never()).getWriter();
  }

  @Test
  void secondAdminEndpointRejectsPlatformAdminWithoutChallengeAuthorization() throws Exception {
    HttpServletRequest request = requestWithRole("admin");
    HttpServletResponse response = mock(HttpServletResponse.class);
    when(request.getParameter("adminData")).thenReturn("youAreAnAdminOfAwesomenessWoopWoop");

    new UrlAccess2Admin().doPost(request, response);

    verify(response).sendError(HttpServletResponse.SC_FORBIDDEN);
    verify(response, never()).getWriter();
  }

  @Test
  void firstAdminEndpointKeepsAuthorizedAccess() throws Exception {
    HttpServletRequest request = authorizedRequest("urlAccessOneAdminAuthorized");
    HttpServletResponse response = mock(HttpServletResponse.class);
    StringWriter body = new StringWriter();
    PrintWriter writer = new PrintWriter(body);
    when(response.getWriter()).thenReturn(writer);
    when(request.getParameter("userData")).thenReturn("4816283");

    new UrlAccess1Admin().doPost(request, response);
    writer.flush();

    assertTrue(body.toString().contains("<a>"));
    verify(response, never()).sendError(HttpServletResponse.SC_FORBIDDEN);
  }

  @Test
  void secondAdminEndpointKeepsAuthorizedAccess() throws Exception {
    HttpServletRequest request = authorizedRequest("urlAccessTwoAdminAuthorized");
    HttpServletResponse response = mock(HttpServletResponse.class);
    StringWriter body = new StringWriter();
    PrintWriter writer = new PrintWriter(body);
    when(response.getWriter()).thenReturn(writer);
    when(request.getParameter("adminData")).thenReturn("youAreAnAdminOfAwesomenessWoopWoop");

    new UrlAccess2Admin().doPost(request, response);
    writer.flush();

    assertTrue(body.toString().contains("<a>"));
    verify(response, never()).sendError(HttpServletResponse.SC_FORBIDDEN);
  }

  private static HttpServletRequest playerRequest() {
    return requestWithRole("player");
  }

  private static HttpServletRequest authorizedRequest(String permission) {
    HttpServletRequest request = requestWithRole("player");
    when(request.getSession(true).getAttribute(permission)).thenReturn(Boolean.TRUE);
    return request;
  }

  private static HttpServletRequest requestWithRole(String role) {
    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpSession session = mock(HttpSession.class);
    when(request.getSession(true)).thenReturn(session);
    when(request.getSession()).thenReturn(session);
    when(request.getRemoteAddr()).thenReturn("127.0.0.1");
    when(session.getAttribute("userRole")).thenReturn(role);
    when(session.getAttribute("userName")).thenReturn("player-one");
    return request;
  }
}
