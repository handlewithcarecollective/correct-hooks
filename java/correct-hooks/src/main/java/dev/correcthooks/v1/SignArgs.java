package dev.correcthooks.v1;

import java.util.UUID;

/** The arguments to the {@link CorrectHooks#sign} function. */
public final class SignArgs {
  /**
   * An id for the webhook.
   *
   * <p>This id should be unique for the event triggering the webhook, and should be reused for any
   * delivery retries.
   */
  public final UUID webhookId;

  /**
   * The webhook consumer's id.
   *
   * <p>This id must be controlled by the webhook producer and not taken as an input from the
   * webhook consumer
   */
  public final UUID recipientId;

  /**
   * The url the webhook is being sent to.
   *
   * <p>Must be the exact url string provided by the webhook consumer.
   */
  public final String targetUrl;

  /** The HTTP method the webhook will be sent with. */
  public final String method;

  /** The exact body of the webhook request as bytes. */
  public final byte[] requestBody;

  /** The {@link SecretSigningKey} the signature will be signed with. */
  public final SecretSigningKey secretSigningKey;

  public SignArgs(
      UUID webhookId,
      UUID recipientId,
      String targetUrl,
      String method,
      byte[] requestBody,
      SecretSigningKey secretSigningKey) {
    this.webhookId = webhookId;
    this.recipientId = recipientId;
    this.targetUrl = targetUrl;
    this.method = method;
    this.requestBody = requestBody;
    this.secretSigningKey = secretSigningKey;
  }
}
