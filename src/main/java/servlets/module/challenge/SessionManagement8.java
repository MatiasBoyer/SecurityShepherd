package servlets.module.challenge;

import dbProcs.Getter;
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
import utils.Hash;
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Session Management Challenge Eight <br>
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
public class SessionManagement8 extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(SessionManagement8.class);
  private static String levelName = "Session Management Challenge Eight";
  private static String levelHash =
      "714d8601c303bbef8b5cabab60b1060ac41f0d96f53b6ea54705bb1ea4316334";

  /**
   * Returns the privileged view only for an authenticated administrator. The browser's
   * "challengeRole" cookie is not an authorization source.
   *
   * @param returnUserRole Red herring
   * @param returnPassword Red herring
   * @param adminDetected Red herring
   */
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    String redherringOne = new String("returnUserRole");
    String redherringTwo = new String("returnPassword");
    String redherringThr = new String("adminDetected");
    PrintWriter out = response.getWriter();
    out.print(getServletInfo());

    // Translation Stuff
    Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
    ResourceBundle errors = ResourceBundle.getBundle("i18n.servlets.errors", locale);
    ResourceBundle bundle =
        ResourceBundle.getBundle(
            "i18n.servlets.challenges.sessionManagement.sessionManagement8", locale);

    try {
      // Setting IpAddress To Log and taking header for original IP if forwarded from proxy
      ShepherdLogManager.setRequestIp(
          request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
      HttpSession ses = request.getSession(true);
      if (Validate.validateSession(ses)) {
        ShepherdLogManager.setRequestIp(
            request.getRemoteAddr(),
            request.getHeader("X-Forwarded-For"),
            ses.getAttribute("userName").toString());
        log.debug(levelName + " servlet accessed by: " + ses.getAttribute("userName").toString());
        String htmlOutput = new String();
        // Only the authenticated session role can grant access to the privileged view.
        if (canAccessPrivilegedView(ses)) {
          log.debug("Authenticated administrator detected");
          String userKey =
              Hash.generateUserSolution(
                  Getter.getModuleResultFromHash(getServletContext().getRealPath(""), levelHash),
                  (String) ses.getAttribute("userName"));
          htmlOutput =
              "<h2 class='title'>"
                  + bundle.getString("response.superUserClub")
                  + "</h2>"
                  + "<p>"
                  + bundle.getString("response.welcomeSuperUser")
                  + " "
                  + "<a>"
                  + userKey
                  + "</a>"
                  + "</p>";
        }
        if (htmlOutput.isEmpty()) {
          log.debug("Challenge Not Complete");
          boolean hackDetected = false;
          hackDetected =
              !(request.getParameter(redherringOne) != null
                  && request.getParameter(redherringTwo) != null
                  && request.getParameter(redherringThr) != null);
          if (!hackDetected) {
            String paramOne = request.getParameter(redherringOne).toString();
            String paramTwo = request.getParameter(redherringTwo).toString();
            String paramThr = request.getParameter(redherringThr).toString();
            log.debug("Param value of " + redherringOne + ":" + paramOne);
            log.debug("Param value of " + redherringTwo + ":" + paramTwo);
            log.debug("Param value of " + redherringThr + ":" + paramThr);
            hackDetected =
                !(paramOne.equalsIgnoreCase("false")
                    && paramTwo.equalsIgnoreCase("false")
                    && paramThr.equalsIgnoreCase("false"));
          }
          if (!hackDetected) {
            htmlOutput =
                "<h2 class='title'>"
                    + bundle.getString("response.notPrivileged")
                    + "</h2>"
                    + "<p>"
                    + bundle.getString("response.notPrivileged.message")
                    + "</p>";
          } else {
            htmlOutput =
                "<h2 class='title'>"
                    + bundle.getString("response.hackDetected")
                    + "</h2>"
                    + "<p>"
                    + bundle.getString("response.hackDetected.message")
                    + "</p>";
          }
        }
        log.debug("Outputting HTML");
        out.write(htmlOutput);
      } else {
        log.error(levelName + " servlet accessed with no session");
      }
    } catch (Exception e) {
      out.write(errors.getString("error.funky"));
      log.fatal(levelName + " - " + e.toString());
    }
  }

  static boolean canAccessPrivilegedView(HttpSession session) {
    return "admin".equals(session.getAttribute("userRole"));
  }
}
