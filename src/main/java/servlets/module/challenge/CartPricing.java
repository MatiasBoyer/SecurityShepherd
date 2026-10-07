package servlets.module.challenge;

/** Shared validation and arithmetic for the fruit-shop challenge orders. */
final class CartPricing {

  private CartPricing() {}

  static int parseQuantity(String amount) {
    int quantity = Integer.parseInt(amount);
    if (quantity < 0) {
      throw new IllegalArgumentException("Quantity cannot be negative");
    }
    return quantity;
  }

  static long total(int pineapple, int orange, int apple, int banana) {
    if (pineapple < 0 || orange < 0 || apple < 0 || banana < 0) {
      throw new IllegalArgumentException("Quantity cannot be negative");
    }
    return (long) pineapple * 30 + (long) orange * 3000 + (long) apple * 45 + (long) banana * 15;
  }

  static long discounted(long cost, int percentOff) {
    if (cost < 0 || percentOff < 0 || percentOff > 100) {
      throw new IllegalArgumentException("Invalid discount");
    }
    return Math.multiplyExact(cost, 100L - percentOff) / 100;
  }
}
