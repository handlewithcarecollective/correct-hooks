package dev.correcthooks.v2;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Retrieves the public verifying key set JSON over HTTP.
 *
 * <p>This is the Java 8 implementation, which uses a synchronous {@link HttpURLConnection}. The jar
 * is a multi-release jar, and on Java 11+ this class is replaced by an implementation that uses the
 * asynchronous {@code java.net.http.HttpClient}.
 */
final class KeySetFetcher {
  private KeySetFetcher() {}

  static JsonNode fetch(URL url, int timeoutMillis) throws IOException {
    HttpURLConnection connection = null;
    try {
      connection = (HttpURLConnection) url.openConnection();
      connection.setRequestMethod("GET");
      connection.setConnectTimeout(timeoutMillis);
      connection.setReadTimeout(timeoutMillis);
      int status = connection.getResponseCode();
      if (status != 200) {
        throw new IOException("Unexpected status code " + status);
      }
      try (InputStream body = connection.getInputStream()) {
        return CorrectHooks.OBJECT_MAPPER.readTree(body);
      }
    } finally {
      if (connection != null) {
        connection.disconnect();
      }
    }
  }
}
