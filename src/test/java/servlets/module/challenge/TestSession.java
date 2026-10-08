package servlets.module.challenge;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpSession;
import org.mockito.stubbing.Answer;

final class TestSession {

  private TestSession() {}

  static HttpSession create() {
    Map<String, Object> attributes = new HashMap<>();
    HttpSession session = mock(HttpSession.class);
    when(session.getAttribute(org.mockito.ArgumentMatchers.anyString()))
        .thenAnswer((Answer<Object>) invocation -> attributes.get(invocation.getArgument(0)));
    org.mockito.Mockito.doAnswer(
            invocation -> {
              attributes.put(invocation.getArgument(0), invocation.getArgument(1));
              return null;
            })
        .when(session)
        .setAttribute(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.any());
    org.mockito.Mockito.doAnswer(
            invocation -> {
              attributes.remove(invocation.getArgument(0));
              return null;
            })
        .when(session)
        .removeAttribute(org.mockito.ArgumentMatchers.anyString());
    return session;
  }
}
