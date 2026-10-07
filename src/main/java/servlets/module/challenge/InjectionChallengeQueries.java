package servlets.module.challenge;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

/** Parameterized database lookups shared by the SQL injection challenges. */
final class InjectionChallengeQueries {

  private InjectionChallengeQueries() {}

  static PreparedStatement customerById(Connection connection, String customerId)
      throws SQLException {
    PreparedStatement statement =
        connection.prepareStatement("SELECT * FROM customers WHERE customerId = ?");
    statement.setString(1, customerId);
    return statement;
  }

  static PreparedStatement customerByAddress(Connection connection, String address)
      throws SQLException {
    PreparedStatement statement =
        connection.prepareStatement("SELECT * FROM customers WHERE customerAddress = ?");
    statement.setString(1, address);
    return statement;
  }

  static PreparedStatement customerByName(Connection connection, String name) throws SQLException {
    PreparedStatement statement =
        connection.prepareStatement("SELECT customerName FROM customers WHERE customerName = ?");
    statement.setString(1, name);
    return statement;
  }

  static PreparedStatement userByCredentials(
      Connection connection, String userName, String password) throws SQLException {
    PreparedStatement statement =
        connection.prepareStatement(
            "SELECT userName FROM users WHERE userName = ? AND userPassword = ?");
    statement.setString(1, userName);
    statement.setString(2, password);
    return statement;
  }

  static PreparedStatement purchaseCoupon(Connection connection, String couponCode)
      throws SQLException {
    PreparedStatement statement =
        connection.prepareStatement(
            "SELECT itemId, perCentOff FROM coupons WHERE couponCode = ? "
                + "UNION SELECT itemId, perCentOff FROM vipCoupons WHERE couponCode = ?");
    statement.setString(1, couponCode);
    statement.setString(2, couponCode);
    return statement;
  }

  static PreparedStatement publicCoupon(Connection connection, String couponCode)
      throws SQLException {
    PreparedStatement statement =
        connection.prepareStatement(
            "SELECT itemId, perCentOff, itemName FROM coupons JOIN items USING (itemId) "
                + "WHERE couponCode = ?");
    statement.setString(1, couponCode);
    return statement;
  }

  static PreparedStatement vipCoupon(Connection connection, String couponCode) throws SQLException {
    PreparedStatement statement =
        connection.prepareStatement(
            "SELECT itemId, perCentOff, itemName FROM vipCoupons JOIN items USING (itemId) "
                + "WHERE couponCode = ?");
    statement.setString(1, couponCode);
    return statement;
  }

  static PreparedStatement userByPin(Connection connection, String pin) throws SQLException {
    PreparedStatement statement =
        connection.prepareStatement("SELECT userName FROM users WHERE userPin = ?");
    statement.setString(1, pin);
    return statement;
  }

  static PreparedStatement userByEmailAndPassword(
      Connection connection, String email, String password) throws SQLException {
    PreparedStatement statement =
        connection.prepareStatement(
            "SELECT userName FROM users WHERE userEmail = ? AND userPassword = ?");
    statement.setString(1, email);
    statement.setString(2, password);
    return statement;
  }

  static PreparedStatement findUser(Connection connection, String address) throws SQLException {
    PreparedStatement statement = connection.prepareStatement("CALL findUser(?)");
    statement.setString(1, address);
    return statement;
  }
}
