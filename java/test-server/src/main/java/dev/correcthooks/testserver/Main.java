package dev.correcthooks.testserver;

import java.io.IOException;

/** Runs the test server for a signature version: {@code --version v1|v2 --port <port>}. */
public final class Main {
  private Main() {}

  public static void main(String[] args) throws IOException {
    String version = null;
    String port = System.getenv("JAVA_CORRECT_HOOKS_TEST_SERVER_PORT");
    for (int i = 0; i < args.length - 1; i++) {
      if (args[i].equals("--version")) {
        version = args[i + 1];
      } else if (args[i].equals("--port")) {
        port = args[i + 1];
      }
    }
    if (port == null) {
      throw new IllegalArgumentException(
          "Missing port: pass --port or set JAVA_CORRECT_HOOKS_TEST_SERVER_PORT");
    }

    if ("v2".equals(version)) {
      V2.main(Integer.parseInt(port));
    } else {
      throw new IllegalArgumentException("Missing or invalid version: pass --version v1 or v2");
    }
  }
}
