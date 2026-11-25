package dev.correcthooks.v1;

/** The arguments to {@link Verifier#verify} and {@link Verifier#verifyWithTime}. */
public final class VerifyArgs {
  /**
   * The url your endpoint is receiving requests at.
   *
   * <p>{@code targetUrl} needs to be the exact string given to the webhook provider.
   */
  public final String targetUrl;

  /** The HTTP method the request was sent with. Can be extracted from the request. */
  public final String method;

  /** The value from the request's {@code correct-hooks-signature-components} header. */
  public final String correctHooksSignatureComponents;

  /** The value from the request's {@code correct-hooks-signature} header. */
  public final String correctHooksSignature;

  /** The raw unparsed request body as bytes. */
  public final byte[] requestBody;

  public VerifyArgs(
      String targetUrl,
      String method,
      String correctHooksSignatureComponents,
      String correctHooksSignature,
      byte[] requestBody) {
    this.targetUrl = targetUrl;
    this.method = method;
    this.correctHooksSignatureComponents = correctHooksSignatureComponents;
    this.correctHooksSignature = correctHooksSignature;
    this.requestBody = requestBody;
  }
}
