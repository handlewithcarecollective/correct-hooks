package dev.correcthooks.testserver;

import static dev.correcthooks.testserver.Http.fail;
import static dev.correcthooks.testserver.Http.ok;
import static dev.correcthooks.testserver.Http.pathId;
import static dev.correcthooks.testserver.Http.readJson;
import static dev.correcthooks.testserver.Http.respond;
import static dev.correcthooks.testserver.Http.respondJson;
import static dev.correcthooks.testserver.Http.route;

import com.fasterxml.jackson.databind.JsonNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import dev.correcthooks.testserver.Http.ApiResponse;
import dev.correcthooks.v1.CorrectHooks;
import dev.correcthooks.v1.CreatePublicVerifyingKeySetException;
import dev.correcthooks.v1.PublicVerifyingKeySet;
import dev.correcthooks.v1.SecretSigningKey;
import dev.correcthooks.v1.SignArgs;
import dev.correcthooks.v1.SignException;
import dev.correcthooks.v1.SignatureData;
import dev.correcthooks.v1.VerifiedData;
import dev.correcthooks.v1.Verifier;
import dev.correcthooks.v1.VerifierConfig;
import dev.correcthooks.v1.VerifyArgs;
import dev.correcthooks.v1.VerifyException;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/** Test server exposing the v1 library over http for the cross library tests. */
final class V1 {
  private V1() {}

  static final class CreatePublicVerifyingKeySetRequest {
    public List<SecretSigningKey> keys;
  }

  static final class SignRequest {
    public String targetUrl;
    public String webhookId;
    public String recipientId;
    public String method;
    public String body;
    public SecretSigningKey signingKey;
  }

  static final class VerifyWithTimeRequest {
    public String recipientId;
    public String targetUrl;
    public String method;
    public String correctHooksSignatureComponents;
    public String correctHooksSignature;
    public String body;
    public long signatureTtlSeconds;
    public PublicVerifyingKeySet publicVerifyingKeySet;
    public long now;
  }

  static final class RegisterPublicVerifyingKeySetRequest {
    public JsonNode publicVerifyingKeySet;
  }

  static final class VerifyWithTimeWithVerifierRequest {
    public String targetUrl;
    public String method;
    public String correctHooksSignatureComponents;
    public String correctHooksSignature;
    public String body;
    public long now;
  }

  private static final Map<UUID, JsonNode> publicVerifyingKeySets = new ConcurrentHashMap<>();
  private static final Map<UUID, Verifier> verifiers = new ConcurrentHashMap<>();

  static void main(int port) throws IOException {
    HttpServer server = Http.createServer(port);

    route(server, "GET", "/health", exchange -> respond(exchange, 200));
    route(
        server,
        "POST",
        "/generate_secret_signing_key",
        exchange -> respondJson(exchange, CorrectHooks.generateSecretSigningKey()));
    route(
        server,
        "POST",
        "/create_public_verifying_key_set",
        V1::createPublicVerifyingKeySetEndpoint);
    route(server, "POST", "/sign", V1::signEndpoint);
    route(server, "POST", "/verify_with_time", V1::verifyWithTimeEndpoint);
    route(
        server,
        "POST",
        "/register_public_verifying_key_set/",
        V1::registerPublicVerifyingKeySet);
    route(server, "GET", "/get_public_verifying_key_set/", V1::getPublicVerifyingKeySet);
    route(server, "POST", "/register_new_verifier/", V1::registerNewVerifier);
    route(
        server, "POST", "/verify_with_time_with_verifier/", V1::verifyWithTimeWithVerifier);

    server.start();
  }

  private static void createPublicVerifyingKeySetEndpoint(
      HttpExchange exchange) throws Exception {
    CreatePublicVerifyingKeySetRequest request =
        readJson(exchange, CreatePublicVerifyingKeySetRequest.class);
    ApiResponse<PublicVerifyingKeySet> response;
    try {
      response = ok(CorrectHooks.createPublicVerifyingKeySet(request.keys));
    } catch (CreatePublicVerifyingKeySetException e) {
      switch (e.getKind()) {
        case INVALID_KEY_FOUND:
          response = fail("InvalidKeyFound");
          break;
        default:
          throw e;
      }
    }
    respondJson(exchange, response);
  }

  private static void signEndpoint(HttpExchange exchange)
      throws Exception {
    SignRequest request = readJson(exchange, SignRequest.class);
    ApiResponse<SignatureData> response;
    try {
      byte[] body = CorrectHooks.decodeBase64(request.body);
      response =
          ok(
              CorrectHooks.sign(
                  new SignArgs(
                      UUID.fromString(request.webhookId),
                      UUID.fromString(request.recipientId),
                      request.targetUrl,
                      request.method,
                      body,
                      request.signingKey)));
    } catch (SignException e) {
      switch (e.getKind()) {
        case INVALID_ARGS:
          response = fail("InvalidArgs");
          break;
        case INVALID_SIGNING_KEY:
          response = fail("InvalidSigningKey");
          break;
        default:
          throw e;
      }
    }
    respondJson(exchange, response);
  }

  private static void verifyWithTimeEndpoint(HttpExchange exchange)
      throws Exception {
    VerifyWithTimeRequest request = readJson(exchange, VerifyWithTimeRequest.class);
    ApiResponse<VerifiedData> response;
    try {
      byte[] body = CorrectHooks.decodeBase64(request.body);
      response =
          ok(
              CorrectHooks.verifyWithTime(
                  new VerifyArgs(
                      request.targetUrl,
                      request.method,
                      request.correctHooksSignatureComponents,
                      request.correctHooksSignature,
                      body),
                  UUID.fromString(request.recipientId),
                  request.signatureTtlSeconds,
                  request.publicVerifyingKeySet,
                  request.now));
    } catch (VerifyException e) {
      response = fail(verifyErrorName(e));
    }
    respondJson(exchange, response);
  }

  private static void registerPublicVerifyingKeySet(HttpExchange exchange)
      throws Exception {
    UUID id = UUID.fromString(pathId(exchange, "/register_public_verifying_key_set/"));
    RegisterPublicVerifyingKeySetRequest request =
        readJson(exchange, RegisterPublicVerifyingKeySetRequest.class);
    if (request.publicVerifyingKeySet != null && !request.publicVerifyingKeySet.isNull()) {
      publicVerifyingKeySets.put(id, request.publicVerifyingKeySet);
    } else {
      publicVerifyingKeySets.remove(id);
    }
    respond(exchange, 200);
  }

  private static void getPublicVerifyingKeySet(HttpExchange exchange)
      throws Exception {
    UUID id = UUID.fromString(pathId(exchange, "/get_public_verifying_key_set/"));
    JsonNode publicVerifyingKeySet = publicVerifyingKeySets.get(id);
    if (publicVerifyingKeySet == null) {
      respond(exchange, 404);
      return;
    }
    respondJson(exchange, publicVerifyingKeySet);
  }

  private static void registerNewVerifier(HttpExchange exchange)
      throws Exception {
    UUID id = UUID.fromString(pathId(exchange, "/register_new_verifier/"));
    VerifierConfig request = readJson(exchange, VerifierConfig.class);
    verifiers.put(id, new Verifier(request));
    respond(exchange, 200);
  }

  private static void verifyWithTimeWithVerifier(HttpExchange exchange)
      throws Exception {
    UUID id = UUID.fromString(pathId(exchange, "/verify_with_time_with_verifier/"));
    VerifyWithTimeWithVerifierRequest request =
        readJson(exchange, VerifyWithTimeWithVerifierRequest.class);
    Verifier verifier = verifiers.get(id);
    if (verifier == null) {
      throw new IllegalStateException("No verifier for id " + id);
    }
    ApiResponse<VerifiedData> response;
    try {
      byte[] body = CorrectHooks.decodeBase64(request.body);
      response =
          ok(
              verifier.verifyWithTime(
                  new VerifyArgs(
                      request.targetUrl,
                      request.method,
                      request.correctHooksSignatureComponents,
                      request.correctHooksSignature,
                      body),
                  request.now));
    } catch (VerifyException e) {
      response = fail(verifyErrorName(e));
    }
    respondJson(exchange, response);
  }

  private static String verifyErrorName(VerifyException e) throws VerifyException {
    switch (e.getKind()) {
      case PUBLIC_VERIFYING_KEY_NOT_FOUND:
        return "PublicVerifyingKeyNotFound";
      case PUBLIC_VERIFYING_KEY_RETRIEVAL_FAILED:
        return "PublicVerifyingKeyRetrievalFailed";
      case INVALID_SIGNATURE:
        return "InvalidSignature";
      case INVALID_PUBLIC_VERIFYING_KEY:
        return "InvalidPublicVerifyingKey";
      default:
        throw e;
    }
  }
}
