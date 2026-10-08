package servlets.module.challenge;

import dbProcs.Constants;
import de.mkammerer.argon2.Argon2Factory;
import de.mkammerer.argon2.Argon2Factory.Argon2Types;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Initial credentials for the five isolated Session Management Two accounts. */
public final class SessionManagement2Credentials {

  // A non-credential seed marker for accounts awaiting initial provisioning.
  static final String PENDING_CREDENTIAL_MARKER = "!s2:init:6d43c8a1";
  private static final String CREDENTIAL_FILE = "SecurityShepherd.session2-initial";
  private static final String USER_QUERY =
      "SELECT userId, userName, userAddress, userPassword FROM"
          + " BrokenAuthAndSessMangChalTwo.users ORDER BY userId FOR UPDATE";
  private static final String UPDATE_QUERY =
      "UPDATE BrokenAuthAndSessMangChalTwo.users SET userPassword = ?"
          + " WHERE userId = ? AND userPassword = ?";
  private static final SecureRandom RANDOM = new SecureRandom();
  private static final String DUMMY_HASH = hashPassword("no-session-two-account");

  private SessionManagement2Credentials() {}

  public static Path credentialFile() {
    return Paths.get(Constants.CATALINA_CONF, CREDENTIAL_FILE);
  }

  /**
   * Rotates unprovisioned or legacy credentials once, then writes the generated passwords to an
   * restricted file in Tomcat's configuration directory. An operator must deliver the file's
   * contents to account owners through a trusted channel and remove it after delivery. No password
   * is included in an HTTP response or application log.
   */
  public static synchronized void provisionIfNeeded(Connection connection, Path credentialFile)
      throws SQLException, IOException {
    boolean originalAutoCommit = connection.getAutoCommit();
    Path pendingFile = credentialFile.resolveSibling(CREDENTIAL_FILE + ".pending");
    boolean committed = false;
    if (originalAutoCommit) {
      connection.setAutoCommit(false);
    }
    try {
      List<Account> accounts = readAccounts(connection);
      List<Account> pendingAccounts = new ArrayList<>();
      for (Account account : accounts) {
        if (!account.passwordHash.startsWith("$argon2id$")) {
          if (!isRecognizedLegacyCredential(account.passwordHash)) {
            throw new SQLException("Unexpected Session Management Two credential state");
          }
          pendingAccounts.add(account);
        }
      }
      if (pendingAccounts.isEmpty()) {
        connection.commit();
        committed = true;
        if (Files.exists(pendingFile)) {
          if (deliveryFileMatchesAccounts(pendingFile, accounts)) {
            Files.move(
                pendingFile,
                credentialFile,
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING);
          } else {
            Files.delete(pendingFile);
          }
        }
        return;
      }

      StringBuilder delivery = existingValidCredentials(credentialFile, pendingFile, accounts);
      Files.deleteIfExists(pendingFile);
      for (Account account : pendingAccounts) {
        String password = generatePassword();
        account.newPasswordHash = hashPassword(password);
        delivery
            .append(account.userName)
            .append('\t')
            .append(account.address)
            .append('\t')
            .append(password)
            .append('\n');
      }

      Files.createFile(
          pendingFile,
          PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
      Files.write(
          pendingFile,
          delivery.toString().getBytes(StandardCharsets.UTF_8),
          StandardOpenOption.TRUNCATE_EXISTING,
          StandardOpenOption.WRITE);

      try (PreparedStatement update = connection.prepareStatement(UPDATE_QUERY)) {
        for (Account account : pendingAccounts) {
          update.setString(1, account.newPasswordHash);
          update.setInt(2, account.id);
          update.setString(3, account.passwordHash);
          if (update.executeUpdate() != 1) {
            throw new SQLException("Session Management Two provisioning was not atomic");
          }
        }
      }
      connection.commit();
      committed = true;
      Files.move(
          pendingFile,
          credentialFile,
          StandardCopyOption.ATOMIC_MOVE,
          StandardCopyOption.REPLACE_EXISTING);
    } catch (SQLException | IOException | RuntimeException e) {
      if (!committed) {
        connection.rollback();
        Files.deleteIfExists(pendingFile);
      }
      throw e;
    } finally {
      if (originalAutoCommit) {
        connection.setAutoCommit(true);
      }
    }
  }

  static String hashPassword(String password) {
    char[] candidate = password.toCharArray();
    try {
      return Argon2Factory.create(Argon2Types.ARGON2id).hash(2, 19456, 1, candidate);
    } finally {
      Arrays.fill(candidate, '\0');
    }
  }

  static boolean passwordMatches(String storedHash, String submittedPassword) {
    boolean hasCredential = storedHash != null && storedHash.startsWith("$argon2id$");
    String hashToCheck = hasCredential ? storedHash : DUMMY_HASH;
    char[] candidate = submittedPassword == null ? new char[0] : submittedPassword.toCharArray();
    try {
      boolean matches = Argon2Factory.create(Argon2Types.ARGON2id).verify(hashToCheck, candidate);
      return hasCredential && matches;
    } catch (IllegalArgumentException e) {
      return false;
    } finally {
      Arrays.fill(candidate, '\0');
    }
  }

  private static List<Account> readAccounts(Connection connection) throws SQLException {
    List<Account> accounts = new ArrayList<>();
    try (PreparedStatement query = connection.prepareStatement(USER_QUERY);
        ResultSet rows = query.executeQuery()) {
      while (rows.next()) {
        accounts.add(
            new Account(
                rows.getInt("userId"),
                rows.getString("userName"),
                rows.getString("userAddress"),
                rows.getString("userPassword")));
      }
    }
    return accounts;
  }

  private static StringBuilder existingValidCredentials(
      Path credentialFile, Path pendingFile, List<Account> accounts) throws IOException {
    Map<String, String> validLines = new LinkedHashMap<>();
    collectValidCredentials(credentialFile, accounts, validLines);
    collectValidCredentials(pendingFile, accounts, validLines);
    StringBuilder existing = new StringBuilder();
    for (String line : validLines.values()) {
      existing.append(line).append('\n');
    }
    return existing;
  }

  private static void collectValidCredentials(
      Path file, List<Account> accounts, Map<String, String> validLines) throws IOException {
    if (Files.exists(file) && !Files.isSymbolicLink(file)) {
      for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
        if (credentialLineMatchesAccount(line, accounts)) {
          validLines.put(line.substring(0, line.lastIndexOf('\t')), line);
        }
      }
    }
  }

  private static boolean deliveryFileMatchesAccounts(Path path, List<Account> accounts)
      throws IOException {
    if (Files.isSymbolicLink(path)) {
      return false;
    }
    List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
    if (lines.isEmpty()) {
      return false;
    }
    for (String line : lines) {
      if (!credentialLineMatchesAccount(line, accounts)) {
        return false;
      }
    }
    return true;
  }

  private static boolean credentialLineMatchesAccount(String line, List<Account> accounts) {
    String[] fields = line.split("\\t", -1);
    if (fields.length != 3) {
      return false;
    }
    for (Account account : accounts) {
      if (account.userName.equals(fields[0]) && account.address.equals(fields[1])) {
        return passwordMatches(account.passwordHash, fields[2]);
      }
    }
    return false;
  }

  private static boolean isRecognizedLegacyCredential(String storedHash) {
    return PENDING_CREDENTIAL_MARKER.equals(storedHash)
        || "default".equals(storedHash)
        || (storedHash != null && storedHash.matches("(?i)[0-9a-f]{40}"));
  }

  private static String generatePassword() {
    byte[] randomBytes = new byte[32];
    RANDOM.nextBytes(randomBytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
  }

  private static final class Account {
    private final int id;
    private final String userName;
    private final String address;
    private final String passwordHash;
    private String newPasswordHash;

    private Account(int id, String userName, String address, String passwordHash) {
      this.id = id;
      this.userName = userName;
      this.address = address;
      this.passwordHash = passwordHash;
    }
  }
}
