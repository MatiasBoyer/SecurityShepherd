package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.PrintWriter;
import java.io.StringWriter;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Element;
import org.junit.jupiter.api.Test;

class XssChallengeResponseTest {

  @Test
  void searchResultsRenderSubmittedTextWithoutCreatingElements() throws Exception {
    HttpServlet[] challenges = {
      new XssChallengeOne(), new XssChallengeTwo(), new XssChallengeThree()
    };
    for (HttpServlet challenge : challenges) {
      String result = post(challenge, "<script>alert(1)</script>");
      assertTrue(Jsoup.parse(result).select("script").isEmpty());
      assertTrue(
          Jsoup.parse(result).select("p").last().text().contains("<script>alert(1)</script>"));
      String imageResult = post(challenge, "<img src=x onerror=alert(1)>");
      assertTrue(Jsoup.parse(imageResult).select("img").isEmpty());
    }
  }

  @Test
  void linkResultsRejectInjectedAttributesAndKeepOrdinaryHttpLinks() throws Exception {
    HttpServlet[] challenges = {
      new XssChallengeFour(), new XssChallengeFive(), new XssChallengeSix()
    };
    for (HttpServlet challenge : challenges) {
      String valid = post(challenge, "https://example.com/path?item=1&count=2");
      Element link = Jsoup.parse(valid).selectFirst("a[href]");
      assertEquals("https://example.com/path?item=1&count=2", link.attr("href"));

      String attack = post(challenge, "https://example.com/\" onmouseover=\"alert(1)");
      Element safeLink = Jsoup.parse(attack).selectFirst("a[href]");
      assertFalse(safeLink.hasAttr("onmouseover"));
      assertTrue(safeLink.attr("href").startsWith("https://"));

      String encodedEntity = post(challenge, "https://example.com/?q=&quot;onmouseover=alert(1)");
      Element entityLink = Jsoup.parse(encodedEntity).selectFirst("a[href]");
      assertEquals("https://example.com/?q=&quot;onmouseover=alert(1)", entityLink.attr("href"));
      assertFalse(entityLink.hasAttr("onmouseover"));
    }
  }

  private static String post(HttpServlet challenge, String searchTerm) throws Exception {
    HttpSession session = mock(HttpSession.class);
    when(session.getAttribute("userRole")).thenReturn("player");
    when(session.getAttribute("userName")).thenReturn("xss-test-user");
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getMethod()).thenReturn("POST");
    when(request.getSession()).thenReturn(session);
    when(request.getSession(true)).thenReturn(session);
    when(request.getRemoteAddr()).thenReturn("127.0.0.1");
    when(request.getCookies()).thenReturn(new Cookie[] {new Cookie("token", "123456")});
    when(request.getParameter("csrfToken")).thenReturn("123456");
    when(request.getParameter("searchTerm")).thenReturn(searchTerm);
    HttpServletResponse response = mock(HttpServletResponse.class);
    StringWriter output = new StringWriter();
    when(response.getWriter()).thenReturn(new PrintWriter(output));
    challenge.service(request, response);
    return output.toString();
  }
}
