package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import javax.servlet.ServletContext;
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

  @Test
  void platformAdministratorGetsGenericAcknowledgementWithoutSubuserAccess() throws Exception {
    HttpSession session = TestSession.create();
    session.setAttribute("userName", "admin");
    session.setAttribute("userRole", "admin");
    String token = SessionChallengeSecurity.issueActionToken(session);
    HttpServletRequest request = resetRequest(session, "owner@example.test", token);
    HttpServletResponse response = mock(HttpServletResponse.class);
    StringWriter output = new StringWriter();
    PrintWriter writer = new PrintWriter(output);
    when(response.getWriter()).thenReturn(writer);

    new SessionManagement2ChangePassword().doPost(request, response);
    writer.flush();

    verify(response, never()).sendError(anyInt());
    assertTrue(output.toString().contains("Password change request received."));
  }

  @Test
  void resetWithInvalidActionTokenIsForbidden() throws Exception {
    HttpSession session = TestSession.create();
    session.setAttribute("userName", "player");
    session.setAttribute("userRole", "player");
    SessionChallengeSecurity.recordSubUser(session, "challenge2", "owner@example.test");
    SessionChallengeSecurity.issueActionToken(session);
    HttpServletRequest request = resetRequest(session, "owner@example.test", "invalid-token");
    HttpServletResponse response = mock(HttpServletResponse.class);
    when(response.getWriter()).thenReturn(new PrintWriter(new StringWriter()));

    new SessionManagement2ChangePassword().doPost(request, response);

    verify(response).sendError(HttpServletResponse.SC_FORBIDDEN);

    HttpServletResponse missingTokenResponse = mock(HttpServletResponse.class);
    when(missingTokenResponse.getWriter()).thenReturn(new PrintWriter(new StringWriter()));
    new SessionManagement2ChangePassword()
        .doPost(resetRequest(session, "owner@example.test", null), missingTokenResponse);
    verify(missingTokenResponse).sendError(HttpServletResponse.SC_FORBIDDEN);
  }

  @Test
  void legacyRecoveryRequestIsUniformAndDoesNotChangePasswords() throws Exception {
    HttpSession session = TestSession.create();
    session.setAttribute("userName", "player");
    session.setAttribute("userRole", "player");
    SessionChallengeSecurity.recordSubUser(session, "challenge2", "owner@example.test");
    SessionChallengeSecurity.issueActionToken(session);
    ServletContext context = mock(ServletContext.class);
    when(context.getRealPath("")).thenReturn("/test");
    SessionManagement2ChangePassword servlet =
        new SessionManagement2ChangePassword() {
          @Override
          public ServletContext getServletContext() {
            return context;
          }

          @Override
          protected Connection getChallengeConnection(String applicationRoot) {
            throw new AssertionError(
                "Legacy recovery request must not access the challenge database");
          }
        };
    String ownerOutput = null;

    for (String email : new String[] {"owner@example.test", "missing@example.test"}) {
      HttpServletRequest request = mock(HttpServletRequest.class);
      when(request.getSession()).thenReturn(session);
      when(request.getSession(true)).thenReturn(session);
      when(request.getRemoteAddr()).thenReturn("127.0.0.1");
      when(request.getParameter("subEmail")).thenReturn(email);
      HttpServletResponse response = mock(HttpServletResponse.class);
      StringWriter output = new StringWriter();
      PrintWriter writer = new PrintWriter(output);
      when(response.getWriter()).thenReturn(writer);

      servlet.doPost(request, response);
      writer.flush();

      verify(response, never()).sendError(anyInt());
      assertTrue(output.toString().contains("Password recovery is unavailable"));
      if (ownerOutput == null) {
        ownerOutput = output.toString();
      } else {
        assertEquals(ownerOutput, output.toString());
      }
    }
  }

  @Test
  void ownerAndOtherEmailsGetSameResponseButOnlyOwnerPasswordChanges() throws Exception {
    HttpSession session = TestSession.create();
    session.setAttribute("userName", "player");
    session.setAttribute("userRole", "player");
    String email = "owner@example.test";
    SessionChallengeSecurity.recordSubUser(session, "challenge2", email);
    String token = SessionChallengeSecurity.issueActionToken(session);
    HttpServletRequest request = resetRequest(session, email, token);
    HttpServletResponse response = mock(HttpServletResponse.class);
    StringWriter output = new StringWriter();
    PrintWriter writer = new PrintWriter(output);
    when(response.getWriter()).thenReturn(writer);
    ServletContext context = mock(ServletContext.class);
    when(context.getRealPath("")).thenReturn("/test");
    Connection connection = mock(Connection.class);
    PreparedStatement select = mock(PreparedStatement.class);
    PreparedStatement update = mock(PreparedStatement.class);
    PreparedStatement commit = mock(PreparedStatement.class);
    ResultSet result = mock(ResultSet.class);
    when(connection.prepareStatement(startsWith("SELECT userId"))).thenReturn(select);
    when(connection.prepareStatement(startsWith("UPDATE users"))).thenReturn(update);
    when(connection.prepareStatement("COMMIT")).thenReturn(commit);
    when(select.executeQuery()).thenReturn(result);
    when(result.next()).thenReturn(true, false);
    when(result.getInt(1)).thenReturn(12);
    SessionManagement2ChangePassword servlet =
        new SessionManagement2ChangePassword() {
          @Override
          public ServletContext getServletContext() {
            return context;
          }

          @Override
          protected Connection getChallengeConnection(String applicationRoot) {
            return connection;
          }
        };

    servlet.doPost(request, response);
    writer.flush();
    String ownerOutput = output.toString();

    for (String otherEmail : new String[] {"other@example.test", "missing@example.test"}) {
      HttpServletResponse otherResponse = mock(HttpServletResponse.class);
      StringWriter otherOutput = new StringWriter();
      PrintWriter otherWriter = new PrintWriter(otherOutput);
      when(otherResponse.getWriter()).thenReturn(otherWriter);
      servlet.doPost(resetRequest(session, otherEmail, token), otherResponse);
      otherWriter.flush();
      verify(otherResponse, never()).sendError(anyInt());
      assertEquals(ownerOutput, otherOutput.toString());
    }

    verify(update).setString(1, "new-private-password");
    verify(update).setString(3, email);
    verify(update, times(1)).executeUpdate();
    verify(connection, times(1)).prepareStatement(startsWith("SELECT userId"));
    verify(response, never()).sendError(anyInt());
    assertTrue(ownerOutput.contains("Password change request received."));
    assertFalse(ownerOutput.contains("new-private-password"));
  }

  private static HttpServletRequest resetRequest(HttpSession session, String email, String token) {
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getSession()).thenReturn(session);
    when(request.getSession(true)).thenReturn(session);
    when(request.getRemoteAddr()).thenReturn("127.0.0.1");
    when(request.getParameter("subEmail")).thenReturn(email);
    when(request.getParameter("newPassword")).thenReturn("new-private-password");
    when(request.getParameter("csrfToken")).thenReturn(token);
    return request;
  }
}
