package dev.correcthooks.v2;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Verifier for signed webhook requests
 *
 * <p>The {@link Verifier} handles retrieving and refreshing the webhook producer's verifying key
 * set for you.
 *
 * <p>Ideally you should create one {@link Verifier} when your backend instance starts and reuse it
 * for all requests sent to that backend instance. A {@link Verifier} is thread safe.
 */
public final class Verifier {
  private static final int HTTP_TIMEOUT_MILLIS = 10_000;

  private static final class PublicVerifyingKeySetData {
    final PublicVerifyingKeySet keySet;
    final long refreshedAt;
    final UUID refreshId;

    PublicVerifyingKeySetData(PublicVerifyingKeySet keySet, long refreshedAt, UUID refreshId) {
      this.keySet = keySet;
      this.refreshedAt = refreshedAt;
      this.refreshId = refreshId;
    }
  }

  private final URL publicVerifyingKeySetUrl;
  private final long signatureTtlSeconds;
  private final long publicVerifyingKeySetTtlSeconds;
  private volatile PublicVerifyingKeySetData publicVerifyingKeySet;
  private final ReentrantLock publicVerifyingKeySetRefreshLock;

  /** Create a new {@link Verifier}. */
  public Verifier(VerifierConfig config) {
    this.publicVerifyingKeySetUrl = config.publicVerifyingKeySetUrl;
    this.signatureTtlSeconds =
        config.signatureTtlSeconds != null
            ? config.signatureTtlSeconds
            : CorrectHooks.DEFAULT_SIGNATURE_TTL_SECONDS;
    this.publicVerifyingKeySetTtlSeconds =
        config.publicVerifyingKeySetTtlSeconds != null
            ? config.publicVerifyingKeySetTtlSeconds
            : CorrectHooks.DEFAULT_PUBLIC_VERIFYING_KEY_SET_TTL_SECONDS;
    this.publicVerifyingKeySet =
        new PublicVerifyingKeySetData(
            new PublicVerifyingKeySet(new ArrayList<PublicJwk>()), 0, UUID.randomUUID());
    this.publicVerifyingKeySetRefreshLock = new ReentrantLock();
  }

  /**
   * Verifies a request and returns validated information from the Correct Hooks request headers.
   *
   * <p>This function confirms that the provided request signature is valid, that the signature has
   * not expired, and that the request was sent to the intended endpoint.
   *
   * @throws VerifyException Any thrown error indicates that the signature could not be verified and
   *     the request should be rejected with a 4xx error.
   */
  public VerifiedData verify(VerifyArgs args) throws VerifyException {
    long now = CorrectHooks.secondsSinceUnixEpoch();
    return verifyWithTime(args, now);
  }

  /**
   * The same as {@link Verifier#verify} but with the current time provided by the caller, which can
   * be useful for testing.
   *
   * @param args The request data to verify.
   * @param now The current time in seconds since Unix epoch.
   */
  public VerifiedData verifyWithTime(VerifyArgs args, long now) throws VerifyException {
    PublicVerifyingKeySetData currentKeySet = currentKeySet();
    if (now > currentKeySet.refreshedAt + publicVerifyingKeySetTtlSeconds) {
      try {
        refreshJwks(currentKeySet.refreshId);
      } catch (VerifyException e) {
        // A failed refresh is not fatal. The existing key set may still verify the request.
      }
    }

    currentKeySet = currentKeySet();
    try {
      return CorrectHooks.verifyWithTime(args, signatureTtlSeconds, currentKeySet.keySet, now);
    } catch (VerifyException e) {
      if (e.getKind() != VerifyException.Kind.PUBLIC_VERIFYING_KEY_NOT_FOUND) {
        throw e;
      }
    }

    try {
      refreshJwks(currentKeySet.refreshId);
    } catch (VerifyException e) {
      throw new VerifyException(VerifyException.Kind.PUBLIC_VERIFYING_KEY_RETRIEVAL_FAILED, e);
    }
    currentKeySet = currentKeySet();
    return CorrectHooks.verifyWithTime(args, signatureTtlSeconds, currentKeySet.keySet, now);
  }

  private void refreshJwks(UUID oldRefreshId) throws VerifyException {
    publicVerifyingKeySetRefreshLock.lock();
    try {
      if (!currentKeySet().refreshId.equals(oldRefreshId)) {
        return;
      }

      PublicVerifyingKeySet keySet;
      try {
        JsonNode keySetJson = KeySetFetcher.fetch(publicVerifyingKeySetUrl, HTTP_TIMEOUT_MILLIS);
        keySet = CorrectHooks.parsePublicVerifyingKeySet(keySetJson);
      } catch (IOException | ClassCastException | IllegalArgumentException e) {
        throw new VerifyException(VerifyException.Kind.PUBLIC_VERIFYING_KEY_RETRIEVAL_FAILED, e);
      }

      long newRefreshTime = CorrectHooks.secondsSinceUnixEpoch();
      publicVerifyingKeySet =
          new PublicVerifyingKeySetData(keySet, newRefreshTime, UUID.randomUUID());
    } finally {
      publicVerifyingKeySetRefreshLock.unlock();
    }
  }

  private PublicVerifyingKeySetData currentKeySet() {
    return publicVerifyingKeySet;
  }
}
