package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;

class DirectObjectProfileAccessTest {

  @Test
  void firstDirectoryKeepsListedProfilesButRejectsHiddenProfile() throws Exception {
    assertTrue(DirectObjectProfileAccess.canViewFirstDirectory("1"));

    HttpServletRequest request = playerRequest("11");
    HttpServletResponse response = mock(HttpServletResponse.class);
    new DirectObject1().doPost(request, response);

    verify(response).sendError(HttpServletResponse.SC_FORBIDDEN);
    verify(response, never()).getWriter();
  }

  @Test
  void secondDirectoryKeepsListedProfilesButRejectsHiddenProfile() throws Exception {
    assertTrue(
        DirectObjectProfileAccess.canViewSecondDirectory("c81e728d9d4c2f636f067f89cc14862c"));

    HttpServletRequest request = playerRequest("c51ce410c124a10e0db5e4b97fc2af39");
    HttpServletResponse response = mock(HttpServletResponse.class);
    new DirectObject2().doPost(request, response);

    verify(response).sendError(HttpServletResponse.SC_FORBIDDEN);
    verify(response, never()).getWriter();
  }

  private static HttpServletRequest playerRequest(String profileId) {
    HttpServletRequest request = mock(HttpServletRequest.class);
    HttpSession session = mock(HttpSession.class);
    when(request.getSession(true)).thenReturn(session);
    when(request.getSession()).thenReturn(session);
    when(request.getRemoteAddr()).thenReturn("127.0.0.1");
    when(request.getParameter("userId[]")).thenReturn(profileId);
    when(session.getAttribute("userRole")).thenReturn("player");
    when(session.getAttribute("userName")).thenReturn("player-one");
    return request;
  }
}
