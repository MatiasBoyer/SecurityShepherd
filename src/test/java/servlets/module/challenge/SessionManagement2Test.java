package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
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

class SessionManagement2Test {

  @Test
  void failedLoginDoesNotRevealWhetherUserNameExists() throws Exception {
    String knownUserWithWrongPassword = failedLoginResponse("admin");
    String unknownUser = failedLoginResponse("unknown-user");

    assertEquals(knownUserWithWrongPassword, unknownUser);
    assertTrue(knownUserWithWrongPassword.contains("Invalid username or password."));
  }

  private static String failedLoginResponse(String userName) throws Exception {
    HttpSession session = TestSession.create();
    session.setAttribute("userName", "player");
    session.setAttribute("userRole", "player");
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getSession()).thenReturn(session);
    when(request.getSession(true)).thenReturn(session);
    when(request.getRemoteAddr()).thenReturn("127.0.0.1");
    when(request.getParameter("subName")).thenReturn(userName);
    when(request.getParameter("subPassword")).thenReturn("wrong-password");
    HttpServletResponse response = mock(HttpServletResponse.class);
    StringWriter output = new StringWriter();
    PrintWriter writer = new PrintWriter(output);
    when(response.getWriter()).thenReturn(writer);

    ServletContext context = mock(ServletContext.class);
    when(context.getRealPath("")).thenReturn("/test");
    Connection connection = mock(Connection.class);
    PreparedStatement commit = mock(PreparedStatement.class);
    PreparedStatement login = mock(PreparedStatement.class);
    ResultSet result = mock(ResultSet.class);
    when(connection.prepareStatement("COMMIT")).thenReturn(commit);
    when(connection.prepareStatement(startsWith("SELECT userName, userAddress"))).thenReturn(login);
    when(login.executeQuery()).thenReturn(result);
    when(result.next()).thenReturn(false);
    SessionManagement2 servlet =
        new SessionManagement2() {
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
    verify(connection, never())
        .prepareStatement("SELECT userAddress FROM users WHERE userName = ?");
    return output.toString();
  }
}
