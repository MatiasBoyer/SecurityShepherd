package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Base64;
import org.junit.jupiter.api.Test;

class BrokenCrypto3Test {

  @Test
  void authenticatedCiphertextCanBeDecrypted() throws Exception {
    String ciphertext = BrokenCrypto3.encrypt("Private message");
    assertEquals("Private message", BrokenCrypto3.decrypt(ciphertext));
    assertNotEquals(ciphertext, BrokenCrypto3.encrypt("Private message"));
  }

  @Test
  void modifiedCiphertextCannotBeDecrypted() throws Exception {
    byte[] ciphertext = Base64.getDecoder().decode(BrokenCrypto3.encrypt("Private message"));
    ciphertext[ciphertext.length - 1] ^= 1;
    assertThrows(
        Exception.class,
        () -> BrokenCrypto3.decrypt(Base64.getEncoder().encodeToString(ciphertext)));
  }

  @Test
  void previousUnauthenticatedXorCiphertextIsRejected() {
    assertThrows(
        Exception.class, () -> BrokenCrypto3.decrypt("IAAAAEkQBhEVBwpDHAFJGhYHSBYEGgocAw=="));
  }
}
