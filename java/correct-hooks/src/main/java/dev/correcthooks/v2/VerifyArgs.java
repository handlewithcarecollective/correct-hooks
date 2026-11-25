package dev.correcthooks.v2;

import java.util.UUID;

/** The arguments to {@link Verifier#verify} and {@link Verifier#verifyWithTime}. */
public final class VerifyArgs {
  /** The target id assigned to a webhook target by the webhook producer. */
  public final UUID targetId;

  /** The HTTP method the request was sent with. Can be extracted from the request. */
  public final String method;

  /** The value from the request's {@code correct-hooks-signature} header. */
  public final String correctHooksSignature;

  /** The raw unparsed request body as bytes. */
  public final byte[] requestBody;

  public VerifyArgs(
      UUID targetId, String method, String correctHooksSignature, byte[] requestBody) {
    this.targetId = targetId;
    this.method = method;
    this.correctHooksSignature = correctHooksSignature;
    this.requestBody = requestBody;
  }
}
