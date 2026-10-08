package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.Test;

class SqlInjectionStoredProcedureTest {

  @Test
  void hidesChallengeResultInSensitiveCustomerComment() {
    String comment = "Well Done! The Result key is example-key";

    String displayed =
        SqlInjectionStoredProcedure.displayComment(
            "44e2bdc1059903f464e5ba9a34b927614d7fee55", comment);

    assertEquals("", displayed);
    assertFalse(displayed.contains("example-key"));
  }

  @Test
  void keepsOrdinaryCustomerComments() {
    assertEquals(
        "Nice &amp; useful",
        SqlInjectionStoredProcedure.displayComment(
            "019ce129ee8960a6b875b20095705d53f8c7b0ca", "Nice & useful"));
  }
}
