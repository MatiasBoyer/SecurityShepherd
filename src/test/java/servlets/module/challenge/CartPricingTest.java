package servlets.module.challenge;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class CartPricingTest {

  @Test
  void rejectsNegativeAmountsInsteadOfMakingAnOrderCheaper() {
    assertThrows(IllegalArgumentException.class, () -> CartPricing.parseQuantity("-1"));
    assertThrows(IllegalArgumentException.class, () -> CartPricing.total(-1, 1, 0, 0));
  }

  @Test
  void largePositiveOrderDoesNotOverflowAnInt() {
    assertEquals(6_442_450_941_000L, CartPricing.total(0, Integer.MAX_VALUE, 0, 0));
  }

  @Test
  void discountsApplyAtAllAdvertisedPercentages() {
    assertEquals(2700L, CartPricing.discounted(3000L, 10));
    assertEquals(1500L, CartPricing.discounted(3000L, 50));
    assertEquals(0L, CartPricing.discounted(3000L, 100));
  }
}
