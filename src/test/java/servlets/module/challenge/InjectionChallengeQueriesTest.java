package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.mongodb.DBObject;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class InjectionChallengeQueriesTest {

  private static final String ATTACK = "' OR '1'='1";

  private Connection connection;
  private PreparedStatement statement;

  @BeforeEach
  void setUp() throws SQLException {
    connection = mock(Connection.class);
    statement = mock(PreparedStatement.class);
    when(connection.prepareStatement(anyString())).thenReturn(statement);
  }

  @Test
  void customerLookupsBindIdsAddressesAndNames() throws SQLException {
    assertBound(
        InjectionChallengeQueries.customerById(connection, ATTACK),
        "SELECT * FROM customers WHERE customerId = ?",
        ATTACK);
    assertBound(
        InjectionChallengeQueries.customerByAddress(connection, ATTACK),
        "SELECT * FROM customers WHERE customerAddress = ?",
        ATTACK);
    assertBound(
        InjectionChallengeQueries.customerByName(connection, ATTACK),
        "SELECT customerName FROM customers WHERE customerName = ?",
        ATTACK);
  }

  @Test
  void userCredentialsBindBothValues() throws SQLException {
    assertBound(
        InjectionChallengeQueries.userByCredentials(connection, ATTACK, ATTACK),
        "SELECT userName FROM users WHERE userName = ? AND userPassword = ?",
        ATTACK);
    verify(statement).setString(2, ATTACK);
  }

  @Test
  void couponLookupsKeepCodeAsData() throws SQLException {
    assertBound(
        InjectionChallengeQueries.purchaseCoupon(connection, ATTACK),
        "SELECT itemId, perCentOff FROM coupons WHERE couponCode = ? "
            + "UNION SELECT itemId, perCentOff FROM vipCoupons WHERE couponCode = ?",
        ATTACK);
    verify(statement).setString(2, ATTACK);
    assertBound(
        InjectionChallengeQueries.publicCoupon(connection, ATTACK),
        "SELECT itemId, perCentOff, itemName FROM coupons JOIN items USING (itemId) "
            + "WHERE couponCode = ?",
        ATTACK);
    assertBound(
        InjectionChallengeQueries.vipCoupon(connection, ATTACK),
        "SELECT itemId, perCentOff, itemName FROM vipCoupons JOIN items USING (itemId) "
            + "WHERE couponCode = ?",
        ATTACK);
  }

  @Test
  void pinAndEmailLoginBindAllCredentials() throws SQLException {
    assertBound(
        InjectionChallengeQueries.userByPin(connection, ATTACK),
        "SELECT userName FROM users WHERE userPin = ?",
        ATTACK);
    assertBound(
        InjectionChallengeQueries.userByEmailAndPassword(connection, ATTACK, ATTACK),
        "SELECT userName FROM users WHERE userEmail = ? AND userPassword = ?",
        ATTACK);
    verify(statement).setString(2, ATTACK);
  }

  @Test
  void storedProcedureCallBindsAddress() throws SQLException {
    assertBound(InjectionChallengeQueries.findUser(connection, ATTACK), "CALL findUser(?)", ATTACK);
  }

  @Test
  void gamerLookupUsesLiteralIdRatherThanJavaScript() {
    DBObject query = NoSqlInjection1.gamerById(ATTACK);
    assertEquals(ATTACK, query.get("_id"));
    assertFalse(query.containsField("$where"));
  }

  private void assertBound(PreparedStatement result, String sql, String input) throws SQLException {
    assertSame(statement, result);
    assertTrue(sql.contains("?"));
    assertFalse(sql.contains(input));
    verify(connection).prepareStatement(sql);
    verify(statement, org.mockito.Mockito.atLeastOnce()).setString(1, input);
  }
}
