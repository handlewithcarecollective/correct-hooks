package dev.correcthooks.v2;

/**
 * Errors thrown by {@link Verifier#verify}. Receiving any of these errors indicates that a request
 * is invalid and should be rejected with a 4xx error code.
 */
public class VerifyException extends Exception {
  private static final long serialVersionUID = 1L;

  /** The possible kinds of a {@link VerifyException}. */
  public enum Kind {
    /**
     * The key needed to verify the request was not found in the verifying key set provided by the
     * webhook provider.
     *
     * <p>If you receive this error consistently, the webhook provider may need to update their
     * published public verifying key set. In some specific cases, this error can also be returned
     * due to an invalid signature.
     */
    PUBLIC_VERIFYING_KEY_NOT_FOUND,
    /**
     * The webhook provider's public verifying key set could not be retrieved.
     *
     * <p>If you get this error, likely either the {@code publicVerifyingKeySetUrl} the {@link
     * Verifier} was created with is incorrect, or the webhook producer's endpoint is unavailable.
     */
    PUBLIC_VERIFYING_KEY_RETRIEVAL_FAILED,
    /** The request's signature is invalid. */
    INVALID_SIGNATURE,
    /**
     * The public verifying key set retrieved from {@code publicVerifyingKeySetUrl} could not be
     * parsed and likely needs to be updated by the webhook producer.
     */
    INVALID_PUBLIC_VERIFYING_KEY
  }

  private final Kind kind;

  public VerifyException(Kind kind) {
    super(kind.name());
    this.kind = kind;
  }

  public VerifyException(Kind kind, Throwable cause) {
    super(kind.name(), cause);
    this.kind = kind;
  }

  public Kind getKind() {
    return kind;
  }
}
