package dev.correcthooks.testserver;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;

/** Small helpers over the JDK's built in http server shared by the v1 and v2 test servers. */
final class Http {
  private Http() {}

  static final ObjectMapper MAPPER =
      new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

  /** The json envelope every endpoint that can fail with a library error responds with. */
  static final class ApiResponse<T> {
    public final T output;
    public final String error;

    ApiResponse(T output, String error) {
      this.output = output;
      this.error = error;
    }
  }

  static <T> ApiResponse<T> ok(T output) {
    return new ApiResponse<>(output, null);
  }

  static <T> ApiResponse<T> fail(String error) {
    return new ApiResponse<>(null, error);
  }

  interface Handler {
    void handle(HttpExchange exchange) throws Exception;
  }

  static HttpServer createServer(int port) throws IOException {
    HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
    server.setExecutor(Executors.newCachedThreadPool());
    return server;
  }

  /** Registers a handler for an exact path or, when {@code path} ends in "/", a path prefix. */
  static void route(HttpServer server, String method, String path, Handler handler) {
    server.createContext(
        path,
        exchange -> {
          try {
            if (!method.equals(exchange.getRequestMethod())) {
              respond(exchange, 405);
              return;
            }
            handler.handle(exchange);
          } catch (Exception e) {
            e.printStackTrace();
            respond(exchange, 500);
          } finally {
            exchange.close();
          }
        });
  }

  /** The {id} segment of a path like /register_new_verifier/{id}. */
  static String pathId(HttpExchange exchange, String prefix) {
    return exchange.getRequestURI().getPath().substring(prefix.length());
  }

  static <T> T readJson(HttpExchange exchange, Class<T> type) throws IOException {
    try (InputStream body = exchange.getRequestBody()) {
      return MAPPER.readValue(body, type);
    }
  }

  static void respondJson(HttpExchange exchange, Object body) throws IOException {
    byte[] bytes = MAPPER.writeValueAsBytes(body);
    exchange.getResponseHeaders().set("Content-Type", "application/json");
    exchange.sendResponseHeaders(200, bytes.length);
    try (OutputStream out = exchange.getResponseBody()) {
      out.write(bytes);
    }
  }

  static void respond(HttpExchange exchange, int status) throws IOException {
    exchange.sendResponseHeaders(status, -1);
  }
}
