package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import dbProcs.Database;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import testUtils.TestProperties;

class SessionManagement2CredentialsIT {

  private static final Logger LOG = LogManager.getLogger(SessionManagement2CredentialsIT.class);
  private static final String SCHEMA = "BrokenAuthAndSessMangChalTwo";

  @BeforeAll
  static void prepareDatabase() throws Exception {
    TestProperties.setTestPropertiesFileDirectory(LOG);
    TestProperties.createMysqlResource();
    TestProperties.ensureSchemaReady(LOG);
  }

  @Test
  void seededAccountsCanBeProvisionedOnceAndLoggedInto(@TempDir Path directory) throws Exception {
    Path file = directory.resolve("initial-credentials");
    Map<String, String> seedHashes = readHashes();
    assertEquals(5, seedHashes.size());
    for (String hash : seedHashes.values()) {
      assertEquals(SessionManagement2Credentials.PENDING_CREDENTIAL_MARKER, hash);
    }

    try (Connection connection = schemaConnection()) {
      SessionManagement2Credentials.provisionIfNeeded(connection, file);
    }
    assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(file));
    Map<String, String> delivered = readCredentials(file);
    assertEquals(5, delivered.size());
    assertEquals(5, new HashSet<>(delivered.values()).size());
    Map<String, String> provisionedHashes = readHashes();
    for (Map.Entry<String, String> entry : delivered.entrySet()) {
      assertTrue(
          SessionManagement2Credentials.passwordMatches(
              provisionedHashes.get(entry.getKey()), entry.getValue()));
      assertFalse(
          SessionManagement2Credentials.passwordMatches(
              provisionedHashes.get(entry.getKey()), "default"));
    }

    String firstDelivery = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
    try (Connection connection = schemaConnection()) {
      SessionManagement2Credentials.provisionIfNeeded(connection, file);
    }
    assertEquals(firstDelivery, new String(Files.readAllBytes(file), StandardCharsets.UTF_8));
    assertEquals(provisionedHashes, readHashes());

    String loginOutput = loginAs("admin", delivered.get("admin"));
    assertTrue(loginOutput.contains("admin"));
    assertTrue(loginOutput.contains("<a>"));

    try (Connection connection = schemaConnection();
        PreparedStatement reset =
            connection.prepareStatement("UPDATE users SET userPassword = ? WHERE userName = ?")) {
      reset.setString(1, SessionManagement2Credentials.PENDING_CREDENTIAL_MARKER);
      reset.setString(2, "admin");
      assertEquals(1, reset.executeUpdate());
    }
    try (Connection connection = schemaConnection()) {
      SessionManagement2Credentials.provisionIfNeeded(connection, file);
    }
    Map<String, String> mixedHashes = readHashes();
    for (String name : provisionedHashes.keySet()) {
      if ("admin".equals(name)) {
        assertNotEquals(provisionedHashes.get(name), mixedHashes.get(name));
      } else {
        assertEquals(provisionedHashes.get(name), mixedHashes.get(name));
      }
    }
    Map<String, String> mixedDelivery = readCredentials(file);
    assertEquals(5, mixedDelivery.size());
    assertNotEquals(delivered.get("admin"), mixedDelivery.get("admin"));
    for (Map.Entry<String, String> entry : mixedDelivery.entrySet()) {
      assertTrue(
          SessionManagement2Credentials.passwordMatches(
              mixedHashes.get(entry.getKey()), entry.getValue()));
    }
  }

  @Test
  void failedCommitPreservesPreviousDelivery(@TempDir Path directory) throws Exception {
    Path file = directory.resolve("initial-credentials");
    Files.write(file, "previous-delivery".getBytes(StandardCharsets.UTF_8));
    Connection connection = mock(Connection.class);
    PreparedStatement select = mock(PreparedStatement.class);
    PreparedStatement update = mock(PreparedStatement.class);
    ResultSet rows = mock(ResultSet.class);
    when(connection.getAutoCommit()).thenReturn(true);
    when(connection.prepareStatement(startsWith("SELECT userId"))).thenReturn(select);
    when(connection.prepareStatement(startsWith("UPDATE"))).thenReturn(update);
    when(select.executeQuery()).thenReturn(rows);
    when(rows.next()).thenReturn(true, false);
    when(rows.getInt("userId")).thenReturn(12);
    when(rows.getString("userName")).thenReturn("admin");
    when(rows.getString("userAddress")).thenReturn("admin@example.test");
    when(rows.getString("userPassword"))
        .thenReturn(SessionManagement2Credentials.PENDING_CREDENTIAL_MARKER);
    when(update.executeUpdate()).thenReturn(1);
    doThrow(new SQLException("commit failed")).when(connection).commit();

    assertThrows(
        SQLException.class,
        () -> SessionManagement2Credentials.provisionIfNeeded(connection, file));
    assertEquals("previous-delivery", new String(Files.readAllBytes(file), StandardCharsets.UTF_8));
    assertFalse(Files.exists(directory.resolve("SecurityShepherd.session2-initial.pending")));
    verify(connection).rollback();
  }

  private static Map<String, String> readHashes() throws SQLException {
    Map<String, String> hashes = new HashMap<>();
    try (Connection connection = schemaConnection();
        PreparedStatement query =
            connection.prepareStatement("SELECT userName, userPassword FROM users");
        ResultSet rows = query.executeQuery()) {
      while (rows.next()) {
        hashes.put(rows.getString("userName"), rows.getString("userPassword"));
      }
    }
    return hashes;
  }

  private static Map<String, String> readCredentials(Path file) throws Exception {
    Map<String, String> delivered = new HashMap<>();
    List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
    for (String line : lines) {
      String[] fields = line.split("\\t", -1);
      assertEquals(3, fields.length);
      assertTrue(fields[2].length() >= 40);
      delivered.put(fields[0], fields[2]);
    }
    return delivered;
  }

  private static Connection schemaConnection() throws SQLException {
    try {
      Connection connection = Database.getDatabaseConnection(null, true);
      connection.setCatalog(SCHEMA);
      return connection;
    } catch (IOException e) {
      throw new SQLException("Unable to open test database", e);
    }
  }

  private static String loginAs(String name, String password) throws Exception {
    HttpSession session = TestSession.create();
    session.setAttribute("userName", "player");
    session.setAttribute("userRole", "player");
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getSession()).thenReturn(session);
    when(request.getSession(true)).thenReturn(session);
    when(request.getRemoteAddr()).thenReturn("127.0.0.1");
    when(request.getParameter("subName")).thenReturn(name);
    when(request.getParameter("subPassword")).thenReturn(password);
    HttpServletResponse response = mock(HttpServletResponse.class);
    StringWriter output = new StringWriter();
    PrintWriter writer = new PrintWriter(output);
    when(response.getWriter()).thenReturn(writer);
    ServletContext context = mock(ServletContext.class);
    when(context.getRealPath("")).thenReturn("/test");
    SessionManagement2 servlet =
        new SessionManagement2() {
          @Override
          public ServletContext getServletContext() {
            return context;
          }

          @Override
          protected void ensureInitialCredentials(String applicationRoot) {}

          @Override
          protected Connection getChallengeConnection(String applicationRoot) throws SQLException {
            return schemaConnection();
          }
        };
    servlet.doPost(request, response);
    writer.flush();
    verify(request).changeSessionId();
    return output.toString();
  }
}
