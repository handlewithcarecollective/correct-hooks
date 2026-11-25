package dev.correcthooks.v2;

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
   * The target_id for the webhook.
   *
   * <p>This is a unique id assigned to a target endpoint when a user registers an it for webhook
   * delivery. If the same endpoint is registered more than once, a new unique id should be
   * assigned every time. This is similar to how an auth system using hmac signatures assigns a
   * unique secret key to every target endpoint, except that the target id is not secret. This id
   * must be controlled by the webhook producer and not taken as an input from the webhook
   * consumer.
   */
  public final UUID targetId;

  /** The HTTP method the webhook will be sent with. */
  public final String method;

  /** The exact body of the webhook request as bytes. */
  public final byte[] requestBody;

  /** The {@link SecretSigningKey} the signature will be signed with. */
  public final SecretSigningKey secretSigningKey;

  public SignArgs(
      UUID webhookId,
      UUID targetId,
      String method,
      byte[] requestBody,
      SecretSigningKey secretSigningKey) {
    this.webhookId = webhookId;
    this.targetId = targetId;
    this.method = method;
    this.requestBody = requestBody;
    this.secretSigningKey = secretSigningKey;
  }
}
