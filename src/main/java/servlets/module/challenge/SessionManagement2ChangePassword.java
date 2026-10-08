package servlets.module.challenge;

import dbProcs.Database;
import dbProcs.Getter;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
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
 * Session Management Challenge Two - Password Reset Servlet Does not return result key <br>
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
public class SessionManagement2ChangePassword extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(SessionManagement2ChangePassword.class);
  private static String levelName = "Session Management Challenge Two (Change Pass)";
  public static String levelHash =
      "f5ddc0ed2d30e597ebacf5fdd117083674b19bb92ffc3499121b9e6a12c92959";
  private static final String UNINITIALIZED_PASSWORD = "default";

  /**
   * Changes a sub-application password for its authenticated owner. A Security Shepherd
   * administrator can initialize only the sub-application account with the same username after
   * reauthenticating with the current platform password.
   *
   * @param subEmail Sub schema user email address
   * @param newPassword New password chosen by the authenticated user
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
            "i18n.servlets.challenges.sessionManagement.sessionManagement2", locale);

    if (Validate.validateSession(ses)) {
      ShepherdLogManager.setRequestIp(
          request.getRemoteAddr(),
          request.getHeader("X-Forwarded-For"),
          ses.getAttribute("userName").toString());
      log.debug(levelName + " servlet accessed by: " + ses.getAttribute("userName").toString());
      PrintWriter out = response.getWriter();
      out.print(getServletInfo());

      String htmlOutput = new String();
      log.debug(levelName + " Servlet accessed");
      try {
        log.debug("Getting Challenge Parameter");
        Object emailObj = request.getParameter("subEmail");
        String subEmail = Validate.validateParameter(emailObj, 128);
        String newPassword = Validate.validateParameter(request.getParameter("newPassword"), 512);
        String csrfToken = request.getParameter("csrfToken");
        if (!SessionChallengeSecurity.hasActionToken(ses, csrfToken)) {
          response.sendError(HttpServletResponse.SC_FORBIDDEN);
          return;
        }
        boolean ownerAuthorized =
            SessionChallengeSecurity.mayChangeChallenge2Password(ses, subEmail, csrfToken);
        String ApplicationRoot = getServletContext().getRealPath("");
        boolean adminReauthenticated = false;
        String adminPassword = request.getParameter("adminPassword");
        if (!ownerAuthorized
            && SessionChallengeSecurity.isPlatformAdmin(ses)
            && adminPassword != null
            && !adminPassword.isEmpty()
            && adminPassword.length() <= 512) {
          String[] admin =
              Getter.authUser(
                  ApplicationRoot, (String) ses.getAttribute("userName"), adminPassword);
          adminReauthenticated =
              admin != null
                  && admin.length > 2
                  && "admin".equals(admin[2])
                  && admin[0].equals(ses.getAttribute("userStamp"))
                  && admin[1].equals(ses.getAttribute("userName"));
        }
        boolean bootstrapAuthorized =
            SessionChallengeSecurity.mayBootstrapChallenge2Password(
                ses, csrfToken, adminReauthenticated);
        if (!ownerAuthorized && !bootstrapAuthorized) {
          response.sendError(HttpServletResponse.SC_FORBIDDEN);
          return;
        }
        if (!Validate.isValidPassword(newPassword)) {
          response.sendError(HttpServletResponse.SC_BAD_REQUEST);
          return;
        }

        try (Connection conn =
            Database.getChallengeConnection(ApplicationRoot, "BrokenAuthAndSessMangChalTwo")) {
          String selectSql =
              bootstrapAuthorized
                  ? "SELECT userId FROM users WHERE BINARY userAddress = BINARY ?"
                      + " AND BINARY userName = BINARY ?"
                      + " AND userPassword = ?"
                  : "SELECT userId FROM users WHERE userAddress = ?";
          int targetUserId;
          try (PreparedStatement target = conn.prepareStatement(selectSql)) {
            target.setString(1, subEmail);
            if (bootstrapAuthorized) {
              target.setString(2, (String) ses.getAttribute("userName"));
              target.setString(3, UNINITIALIZED_PASSWORD);
            }
            try (ResultSet users = target.executeQuery()) {
              if (!users.next()) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN);
                return;
              }
              targetUserId = users.getInt(1);
              if (users.next()) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN);
                return;
              }
            }
          }

          String updateSql =
              bootstrapAuthorized
                  ? "UPDATE users SET userPassword = SHA(?) WHERE userId = ?"
                      + " AND BINARY userAddress = BINARY ?"
                      + " AND BINARY userName = BINARY ? AND userPassword = ?"
                  : "UPDATE users SET userPassword = SHA(?) WHERE userId = ? AND userAddress = ?";
          try (PreparedStatement update = conn.prepareStatement(updateSql)) {
            update.setString(1, newPassword);
            update.setInt(2, targetUserId);
            update.setString(3, subEmail);
            if (bootstrapAuthorized) {
              update.setString(4, (String) ses.getAttribute("userName"));
              update.setString(5, UNINITIALIZED_PASSWORD);
            }
            int updated = update.executeUpdate();
            if (bootstrapAuthorized && updated != 1) {
              response.sendError(HttpServletResponse.SC_FORBIDDEN);
              return;
            }
          }
          try (PreparedStatement commit = conn.prepareStatement("COMMIT")) {
            commit.execute();
          }
          htmlOutput = bundle.getString("response.changed");
        } catch (SQLException e) {
          log.error(levelName + " SQL Error: " + e.toString());
          response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
          return;
        }
        log.debug("Outputting HTML");
        out.write(htmlOutput);
      } catch (Exception e) {
        out.write(errors.getString("error.funky"));
        log.fatal(levelName + " - " + e.toString());
      }
    } else {
      log.error(levelName + " servlet accessed with no session");
      response.sendError(HttpServletResponse.SC_FORBIDDEN);
    }
  }
}
