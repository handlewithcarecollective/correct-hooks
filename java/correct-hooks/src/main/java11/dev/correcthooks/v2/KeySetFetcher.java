package dev.correcthooks.v2;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Retrieves the public verifying key set JSON over HTTP.
 *
 * <p>This is the Java 11+ implementation, which issues the request asynchronously with {@link
 * HttpClient#sendAsync}. It replaces the Java 8 implementation in the multi-release jar.
 */
final class KeySetFetcher {
  private static final HttpClient CLIENT =
      HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build();

  private KeySetFetcher() {}

  static JsonNode fetch(URL url, int timeoutMillis) throws IOException {
    HttpRequest request;
    try {
      request =
          HttpRequest.newBuilder(url.toURI())
              .GET()
              .timeout(Duration.ofMillis(timeoutMillis))
              .build();
    } catch (URISyntaxException | IllegalArgumentException e) {
      throw new IOException("Invalid public verifying key set url", e);
    }

    CompletableFuture<JsonNode> future =
        CLIENT
            .sendAsync(request, HttpResponse.BodyHandlers.ofByteArray())
            .thenApply(response -> {
              if (response.statusCode() != 200) {
                throw new java.io.UncheckedIOException(
                    new IOException("Unexpected status code " + response.statusCode()));
              }
              try {
                return CorrectHooks.OBJECT_MAPPER.readTree(response.body());
              } catch (IOException e) {
                throw new java.io.UncheckedIOException(e);
              }
            });

    try {
      return future.get(timeoutMillis, TimeUnit.MILLISECONDS);
    } catch (InterruptedException e) {
      future.cancel(true);
      Thread.currentThread().interrupt();
      throw new InterruptedIOException("Interrupted while retrieving public verifying key set");
    } catch (TimeoutException e) {
      future.cancel(true);
      throw new IOException("Timed out retrieving public verifying key set", e);
    } catch (ExecutionException e) {
      Throwable cause = e.getCause();
      if (cause instanceof java.io.UncheckedIOException) {
        cause = cause.getCause();
      }
      if (cause instanceof IOException) {
        throw (IOException) cause;
      }
      throw new IOException(cause);
    }
  }
}
