package servlets.module.challenge;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/** Server-side access policy for the profiles exposed by the two directory challenges. */
final class DirectObjectProfileAccess {

  private static final Set<String> FIRST_DIRECTORY =
      Collections.unmodifiableSet(new HashSet<>(Arrays.asList("1", "3", "5", "7", "9")));

  private static final Set<String> SECOND_DIRECTORY =
      Collections.unmodifiableSet(
          new HashSet<>(
              Arrays.asList(
                  "c81e728d9d4c2f636f067f89cc14862c",
                  "eccbc87e4b5ce2fe28308fd9f2a7baf3",
                  "e4da3b7fbbce2345d7772b0674a318d5",
                  "8f14e45fceea167a5a36dedd4bea2543",
                  "6512bd43d9caa6e02c990b0a82652dca")));

  private DirectObjectProfileAccess() {}

  static boolean canViewFirstDirectory(String userId) {
    return FIRST_DIRECTORY.contains(userId);
  }

  static boolean canViewSecondDirectory(String userId) {
    return SECOND_DIRECTORY.contains(userId);
  }
}
