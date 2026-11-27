package dev.correcthooks.v2;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.math.ec.rfc8032.Ed25519;

/** Signing, verification, and key management functions for Correct Hooks signature version v2. */
public final class CorrectHooks {
  private CorrectHooks() {}

  /** The signature version produced by this version of the library. */
  public static final String SIGNATURE_VERSION = "v2";

  static final long DEFAULT_SIGNATURE_TTL_SECONDS = 300;
  static final long DEFAULT_PUBLIC_VERIFYING_KEY_SET_TTL_SECONDS = 300;

  private static final int SECRET_KEY_LENGTH = 32;
  private static final int PUBLIC_KEY_LENGTH = 32;
  private static final int SIGNATURE_LENGTH = 64;

  static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  private static final Set<String> VALID_HTTP_METHODS =
      new HashSet<>(
          Arrays.asList(
              "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"));

  private static final class SignatureMessageComponents {
    final UUID webhookId;
    final UUID keyId;
    final long signedAt;
    final UUID targetId;
    final String method;
    final byte[] requestBody;

    SignatureMessageComponents(
        UUID webhookId,
        UUID keyId,
        long signedAt,
        UUID targetId,
        String method,
        byte[] requestBody) {
      this.webhookId = webhookId;
      this.keyId = keyId;
      this.signedAt = signedAt;
      this.targetId = targetId;
      this.method = method;
      this.requestBody = requestBody;
    }
  }

  /** Generate a new {@link SecretSigningKey}. */
  public static SecretSigningKey generateSecretSigningKey() {
    UUID keyId = UUID.randomUUID();
    Ed25519PrivateKeyParameters signingKey = new Ed25519PrivateKeyParameters(new SecureRandom());
    String secretKey = encodeBase64(signingKey.getEncoded());
    String publicKey = encodeBase64(signingKey.generatePublicKey().getEncoded());
    return new SecretSigningKey(keyId, "OKP", "Ed25519", publicKey, secretKey);
  }

  /**
   * Creates a {@link PublicVerifyingKeySet} from a list of {@link SecretSigningKey}.
   *
   * <p>The returned {@link PublicVerifyingKeySet} can be used to verify requests signed by any of
   * the {@code secretSigningKeys}.
   *
   * @throws CreatePublicVerifyingKeySetException if any of the keys is invalid.
   */
  public static PublicVerifyingKeySet createPublicVerifyingKeySet(
      List<SecretSigningKey> secretSigningKeys) throws CreatePublicVerifyingKeySetException {
    List<PublicJwk> publicJwks = new ArrayList<>();
    for (SecretSigningKey privateKey : secretSigningKeys) {
      try {
        decodeSigningKey(privateKey);
      } catch (IllegalArgumentException e) {
        throw new CreatePublicVerifyingKeySetException(
            CreatePublicVerifyingKeySetException.Kind.INVALID_KEY_FOUND, e);
      }
      publicJwks.add(new PublicJwk(privateKey.kid, "OKP", "Ed25519", privateKey.x));
    }
    return new PublicVerifyingKeySet(publicJwks);
  }

  /**
   * Returns the signature for a webhook request.
   *
   * <p>You must set the request header {@code correct-hooks-signature} to the returned value.
   * Webhook consumers will pass the header value to the verify function. Future versions of Correct
   * Hooks with convenience functions that verify specific framework's request objects will expect
   * the exact header name {@code correct-hooks-signature} to be set.
   *
   * <p>{@code sign} should be called every time a webhook delivery is attempted. The signed headers
   * should not be reused between delivery retries.
   *
   * @throws SignException if the arguments or signing key are invalid.
   */
  public static String sign(SignArgs args) throws SignException {
    UUID webhookId = args.webhookId;
    UUID targetId = args.targetId;
    String method = args.method;
    byte[] requestBody = args.requestBody;
    SecretSigningKey secretSigningKey = args.secretSigningKey;

    if (webhookId.version() != 4) {
      throw new SignException(SignException.Kind.INVALID_ARGS);
    }

    if (targetId.version() != 4) {
      throw new SignException(SignException.Kind.INVALID_ARGS);
    }

    if (!isValidHttpMethod(method)) {
      throw new SignException(SignException.Kind.INVALID_ARGS);
    }

    UUID keyId = secretSigningKey.kid;
    long signedAt = secondsSinceUnixEpoch();

    Ed25519PrivateKeyParameters signingKey;
    try {
      signingKey = decodeSigningKey(secretSigningKey);
    } catch (IllegalArgumentException e) {
      throw new SignException(SignException.Kind.INVALID_SIGNING_KEY, e);
    }

    byte[] signatureMessage =
        constructSignatureMessage(
            new SignatureMessageComponents(
                webhookId, keyId, signedAt, targetId, method, requestBody));

    Ed25519Signer signer = new Ed25519Signer();
    signer.init(true, signingKey);
    signer.update(signatureMessage, 0, signatureMessage.length);
    byte[] signature = signer.generateSignature();

    return encodeSignatureHeader(
        new SignatureHeaderComponents(webhookId, keyId, signedAt, signature));
  }

  /**
   * This function is only public for internal testing purposes and will be made private in a future
   * version of this library.
   */
  public static VerifiedData verifyWithTime(
      VerifyArgs args,
      long signatureTtlSeconds,
      PublicVerifyingKeySet publicVerifyingKeySet,
      long now)
      throws VerifyException {
    UUID targetId = args.targetId;
    String method = args.method;
    String correctHooksSignature = args.correctHooksSignature;
    byte[] requestBody = args.requestBody;

    String signatureComponentsEncoded =
        splitVersionedHeader(correctHooksSignature).get(SIGNATURE_VERSION);
    if (signatureComponentsEncoded == null) {
      throw new VerifyException(VerifyException.Kind.INVALID_SIGNATURE);
    }
    SignatureHeaderComponents signatureComponents;
    try {
      signatureComponents = decodeSignatureHeader(signatureComponentsEncoded);
    } catch (IllegalArgumentException e) {
      throw new VerifyException(VerifyException.Kind.INVALID_SIGNATURE, e);
    }

    if (now - signatureComponents.signedAt > signatureTtlSeconds
        || signatureComponents.signedAt - now > signatureTtlSeconds) {
      throw new VerifyException(VerifyException.Kind.INVALID_SIGNATURE);
    }

    PublicJwk verifyingKeyJwk = null;
    for (PublicJwk key : publicVerifyingKeySet.keys) {
      if (key.kid.equals(signatureComponents.keyId)) {
        verifyingKeyJwk = key;
        break;
      }
    }
    if (verifyingKeyJwk == null) {
      throw new VerifyException(VerifyException.Kind.PUBLIC_VERIFYING_KEY_NOT_FOUND);
    }
    Ed25519PublicKeyParameters verifyingKey;
    try {
      byte[] publicKeyBytes = decodeBase64(verifyingKeyJwk.x);
      if (publicKeyBytes.length != PUBLIC_KEY_LENGTH
          || !Ed25519.validatePublicKeyPartial(publicKeyBytes, 0)) {
        throw new VerifyException(VerifyException.Kind.INVALID_PUBLIC_VERIFYING_KEY);
      }
      verifyingKey = new Ed25519PublicKeyParameters(publicKeyBytes, 0);
    } catch (IllegalArgumentException e) {
      throw new VerifyException(VerifyException.Kind.INVALID_PUBLIC_VERIFYING_KEY, e);
    }

    byte[] signatureMessage =
        constructSignatureMessage(
            new SignatureMessageComponents(
                signatureComponents.webhookId,
                signatureComponents.keyId,
                signatureComponents.signedAt,
                targetId,
                method,
                requestBody));

    if (signatureComponents.signature.length != SIGNATURE_LENGTH) {
      throw new VerifyException(VerifyException.Kind.INVALID_SIGNATURE);
    }

    boolean signatureIsValid;
    try {
      Ed25519Signer verifier = new Ed25519Signer();
      verifier.init(false, verifyingKey);
      verifier.update(signatureMessage, 0, signatureMessage.length);
      signatureIsValid = verifier.verifySignature(signatureComponents.signature);
    } catch (RuntimeException e) {
      throw new VerifyException(VerifyException.Kind.INVALID_SIGNATURE, e);
    }
    if (!signatureIsValid) {
      throw new VerifyException(VerifyException.Kind.INVALID_SIGNATURE);
    }

    return new VerifiedData(signatureComponents.webhookId);
  }

  private static byte[] constructSignatureMessage(SignatureMessageComponents components) {
    String webhookIdBase64 = encodeBase64FromString(components.webhookId.toString());
    String keyIdBase64 = encodeBase64FromString(components.keyId.toString());
    String signedAtBase64 = encodeBase64FromString(Long.toString(components.signedAt));
    String targetIdBase64 = encodeBase64FromString(components.targetId.toString());
    byte[] prefix =
        (webhookIdBase64
                + "."
                + keyIdBase64
                + "."
                + signedAtBase64
                + "."
                + targetIdBase64
                + "."
                + components.method
                + ".")
            .getBytes(StandardCharsets.UTF_8);
    byte[] signatureMessage = Arrays.copyOf(prefix, prefix.length + components.requestBody.length);
    System.arraycopy(
        components.requestBody, 0, signatureMessage, prefix.length, components.requestBody.length);
    return signatureMessage;
  }

  /**
   * This function is only public for internal testing purposes and will be made private in a future
   * version of this library.
   */
  public static Map<String, String> splitVersionedHeader(String header) throws VerifyException {
    Map<String, String> splitHeaders = new HashMap<>();
    for (String versionedValue : header.split(" ", -1)) {
      String[] parts = versionedValue.split(",", -1);
      if (parts.length < 2) {
        continue;
      }
      String version = parts[0];
      String value = parts[1];
      if (splitHeaders.containsKey(version)) {
        throw new VerifyException(VerifyException.Kind.INVALID_SIGNATURE);
      }
      splitHeaders.put(version, value);
    }
    return splitHeaders;
  }

  /**
   * This function is only public for internal testing purposes and will be made private in a future
   * version of this library.
   */
  public static String encodeSignatureHeader(SignatureHeaderComponents components) {
    String webhookIdBase64 = encodeBase64FromString(components.webhookId.toString());
    String keyIdBase64 = encodeBase64FromString(components.keyId.toString());
    String signedAtBase64 = encodeBase64FromString(Long.toString(components.signedAt));
    String signatureBase64 = encodeBase64(components.signature);

    return SIGNATURE_VERSION
        + ","
        + webhookIdBase64
        + "."
        + keyIdBase64
        + "."
        + signedAtBase64
        + "."
        + signatureBase64;
  }

  /**
   * This function is only public for internal testing purposes and will be made private in a future
   * version of this library.
   *
   * @throws IllegalArgumentException if the header is malformed.
   */
  public static SignatureHeaderComponents decodeSignatureHeader(String encodedSignatureComponents) {
    String[] components = encodedSignatureComponents.split("\\.", -1);
    if (components.length != 4) {
      throw new IllegalArgumentException("Invalid component count");
    }
    UUID webhookId = parseUuid(decodeBase64ToString(components[0]));
    UUID keyId = parseUuid(decodeBase64ToString(components[1]));
    long signedAt = parseUnsignedLong(decodeBase64ToString(components[2]));
    byte[] signature = decodeBase64(components[3]);

    return new SignatureHeaderComponents(webhookId, keyId, signedAt, signature);
  }

  /** Parses a key set fetched from a webhook producer. Throws if the key set is malformed. */
  static PublicVerifyingKeySet parsePublicVerifyingKeySet(JsonNode jsonKeySet) {
    // The key set must be an object with exactly one field: keys.
    if (!jsonKeySet.isObject()
        || jsonKeySet.size() != 1
        || !jsonKeySet.has("keys")
        || !jsonKeySet.get("keys").isArray()) {
      throw new IllegalArgumentException("key set parse failed");
    }

    // Keys that are not an exact match for PublicJwk fields give an error and are excluded.
    List<PublicJwk> parsedKeys = new ArrayList<>();
    for (JsonNode key : jsonKeySet.get("keys")) {
      try {
        parsedKeys.add(parsePublicJwk(key));
      } catch (IllegalArgumentException e) {
        continue;
      }
    }

    // Duplicate key ids in a key set are not allowed
    Set<UUID> keyIds = new HashSet<>();
    for (PublicJwk key : parsedKeys) {
      if (!keyIds.add(key.kid)) {
        throw new IllegalArgumentException("found duplicate key id");
      }
    }

    return new PublicVerifyingKeySet(parsedKeys);
  }

  private static PublicJwk parsePublicJwk(JsonNode key) {
    if (!key.isObject() || key.size() != 4) {
      throw new IllegalArgumentException("invalid jwk");
    }
    for (String field : new String[] {"kid", "kty", "crv", "x"}) {
      JsonNode value = key.get(field);
      if (value == null || !value.isTextual()) {
        throw new IllegalArgumentException("invalid jwk");
      }
    }
    return new PublicJwk(
        parseUuid(key.get("kid").asText()),
        key.get("kty").asText(),
        key.get("crv").asText(),
        key.get("x").asText());
  }

  private static boolean isValidHttpMethod(String method) {
    return VALID_HTTP_METHODS.contains(method);
  }

  /** Decodes and validates a {@link SecretSigningKey}. Throws if the key is invalid. */
  private static Ed25519PrivateKeyParameters decodeSigningKey(SecretSigningKey secretSigningKey) {
    byte[] secretKeyBytes = decodeBase64(secretSigningKey.d);
    if (secretKeyBytes.length != SECRET_KEY_LENGTH) {
      throw new IllegalArgumentException("invalid secret key length");
    }
    byte[] publicKeyBytes = decodeBase64(secretSigningKey.x);
    if (publicKeyBytes.length != PUBLIC_KEY_LENGTH) {
      throw new IllegalArgumentException("invalid public key length");
    }
    Ed25519PrivateKeyParameters signingKey = new Ed25519PrivateKeyParameters(secretKeyBytes, 0);
    if (!Arrays.equals(signingKey.generatePublicKey().getEncoded(), publicKeyBytes)) {
      throw new IllegalArgumentException("public key does not match secret key");
    }
    return signingKey;
  }

  /**
   * This function is only public for internal testing purposes and will be made private in a future
   * version of this library.
   */
  public static String encodeBase64(byte[] data) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
  }

  /**
   * This function is only public for internal testing purposes and will be made private in a future
   * version of this library.
   *
   * @throws IllegalArgumentException if the input is not canonical unpadded base64url.
   */
  public static byte[] decodeBase64(String base64Str) {
    byte[] data = Base64.getUrlDecoder().decode(base64Str);
    // java.util.Base64 accepts padding and non-zero trailing bits; require the canonical encoding.
    if (!encodeBase64(data).equals(base64Str)) {
      throw new IllegalArgumentException("non-canonical base64");
    }
    return data;
  }

  private static String encodeBase64FromString(String data) {
    return encodeBase64(data.getBytes(StandardCharsets.UTF_8));
  }

  private static String decodeBase64ToString(String base64Str) {
    return new String(decodeBase64(base64Str), StandardCharsets.UTF_8);
  }

  /** Parses a hyphenated uuid string. {@link UUID#fromString} alone is too lenient. */
  private static UUID parseUuid(String value) {
    if (value.length() != 36) {
      throw new IllegalArgumentException("invalid uuid");
    }
    for (int i = 0; i < 36; i++) {
      char c = value.charAt(i);
      boolean isHyphenPosition = i == 8 || i == 13 || i == 18 || i == 23;
      if (isHyphenPosition ? c != '-' : Character.digit(c, 16) < 0 || c > 'f') {
        throw new IllegalArgumentException("invalid uuid");
      }
    }
    return UUID.fromString(value);
  }

  private static long parseUnsignedLong(String value) {
    if (value.isEmpty()) {
      throw new IllegalArgumentException("invalid timestamp");
    }
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      if (c < '0' || c > '9') {
        throw new IllegalArgumentException("invalid timestamp");
      }
    }
    return Long.parseLong(value);
  }

  /**
   * This function is only public for internal testing purposes and will be made private in a future
   * version of this library.
   */
  public static long secondsSinceUnixEpoch() {
    return System.currentTimeMillis() / 1000;
  }
}
