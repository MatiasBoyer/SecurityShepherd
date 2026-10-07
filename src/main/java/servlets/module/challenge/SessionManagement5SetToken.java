package servlets.module.challenge;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Locale;
import java.util.ResourceBundle;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Session Management Challenge Five SessionManagement5SetToken (Does not Return Result Key)
 *
 * <p>Issues a short-lived reset token to the sub-application account already authenticated in the
 * current server session.
 *
 * <p><br>
 * <br>
 * This file is part of the Security Shepherd Project.
 *
 * <p>The Security Shepherd project is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.<br>
 *
 * <p>The Security Shepherd project is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details.<br>
 *
 * <p>You should have received a copy of the GNU General Public License along with the Security
 * Shepherd project. If not, see <http://www.gnu.org/licenses/>.
 *
 * @author Mark Denihan
 */
public class SessionManagement5SetToken extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(SessionManagement5SetToken.class);
  private static String levelName = "SessionManagement5SetToken";
  public static String levelHash = SessionManagement5.levelHash;

  /**
   * Issues a one-time password reset token for the authenticated sub-application user.
   *
   * @param userName Sub schema user name
   */
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    // Setting IpAddress To Log and taking header for original IP if forwarded from proxy
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    HttpSession ses = request.getSession(true);

    // Translation Stuff
    Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
    ResourceBundle errors = ResourceBundle.getBundle("i18n.servlets.errors", locale);
    ResourceBundle bundle =
        ResourceBundle.getBundle(
            "i18n.servlets.challenges.sessionManagement.sessionManagement5", locale);

    if (Validate.validateSession(ses)) {
      ShepherdLogManager.setRequestIp(
          request.getRemoteAddr(),
          request.getHeader("X-Forwarded-For"),
          ses.getAttribute("userName").toString());
      log.debug(levelName + " servlet accessed by: " + ses.getAttribute("userName").toString());
      PrintWriter out = response.getWriter();
      out.print(getServletInfo());

      log.debug(levelName + " Servlet Accessed");
      try {
        String userName = Validate.validateParameter(request.getParameter("subUserName"), 32);
        if (!SessionChallengeSecurity.isSubUser(ses, "challenge5", userName)
            || !SessionChallengeSecurity.hasActionToken(ses, request.getParameter("csrfToken"))) {
          response.sendError(HttpServletResponse.SC_FORBIDDEN);
          return;
        }
        String token = SessionChallengeSecurity.issueResetToken(ses, userName);
        response.setHeader("Cache-Control", "no-store");
        out.write(bundle.getString("setToken.token") + " <code>" + token + "</code>");
      } catch (Exception e) {
        out.write(errors.getString("error.funky"));
        log.fatal(levelName + " - " + e.toString());
      }
    } else {
      log.error(levelName + " servlet accessed with no session");
    }
  }
}
