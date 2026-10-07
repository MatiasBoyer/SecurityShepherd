package servlets.module.challenge;

import dbProcs.Database;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
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
 * Session Management Challenge Five - Change Password This is a level function - DOES NOT RETURN
 * KEY <br>
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
public class SessionManagement5ChangePassword extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(SessionManagement5ChangePassword.class);
  private static String levelName = "Session Management Challenge Five (Change Password)";

  // private static String levelResult = ""; //This Servlet does not return a result

  /**
   * Changes the password for the sub-application account authenticated in this session after
   * consuming its one-time reset token.
   *
   * @param userName Account authenticated in the server session
   * @param newPassword the password which to use to update an accounts password
   * @param resetPasswordToken One-time reset token
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
      try {
        String userName = Validate.validateParameter(request.getParameter("userName"), 32);
        String newPassword = Validate.validateParameter(request.getParameter("newPassword"), 512);
        String token = Validate.validateParameter(request.getParameter("resetPasswordToken"), 128);
        if (!SessionChallengeSecurity.isSubUser(ses, "challenge5", userName)
            || !SessionChallengeSecurity.hasActionToken(ses, request.getParameter("csrfToken"))) {
          response.sendError(HttpServletResponse.SC_FORBIDDEN);
          return;
        }
        if (newPassword.length() < 12) {
          out.write("<p>" + bundle.getString("changePass.failure") + "</p>");
          return;
        }
        if (!SessionChallengeSecurity.consumeResetToken(ses, userName, token)) {
          response.sendError(HttpServletResponse.SC_FORBIDDEN);
          return;
        }
        String applicationRoot = getServletContext().getRealPath("");
        try (Connection conn =
            Database.getChallengeConnection(applicationRoot, "BrokenAuthAndSessMangChalFive")) {
          try (PreparedStatement statement =
              conn.prepareStatement("UPDATE users SET userPassword = SHA(?) WHERE userName = ?")) {
            statement.setString(1, newPassword);
            statement.setString(2, userName);
            statement.executeUpdate();
          }
          try (PreparedStatement commit = conn.prepareStatement("COMMIT")) {
            commit.execute();
          }
        }
        out.write("<p>" + bundle.getString("changePass.success") + "</p>");
      } catch (Exception e) {
        out.write(errors.getString("error.funky"));
        log.fatal(levelName + " - Change Password - " + e.toString());
      }
    } else {
      log.error(levelName + " servlet accessed with no session");
    }
  }
}
