package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.sql.Connection;
import java.sql.PreparedStatement;
import org.junit.jupiter.api.Test;

class SessionManagementQuestionLookupTest {

  @Test
  void lookupBindsEvenAnInjectionShapedAddressAsData() throws Exception {
    Connection connection = mock(Connection.class);
    PreparedStatement statement = mock(PreparedStatement.class);
    String query = "SELECT secretQuestion FROM users WHERE userAddress = ?";
    String address = "x@example.com\" OR 1=1 --";
    when(connection.prepareStatement(query)).thenReturn(statement);

    assertSame(
        statement, SessionManagement6SecretQuestion.prepareQuestionLookup(connection, address));

    verify(connection).prepareStatement(query);
    verify(statement).setString(1, address);
  }
}
