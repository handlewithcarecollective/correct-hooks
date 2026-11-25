package dev.correcthooks.v1;

import java.util.UUID;

/**
 * This class is only public for internal testing purposes and will be made private in a future
 * version of this library.
 */
public final class SignatureComponents {
  public final UUID webhookId;
  public final UUID keyId;
  public final long signedAt;

  public SignatureComponents(UUID webhookId, UUID keyId, long signedAt) {
    this.webhookId = webhookId;
    this.keyId = keyId;
    this.signedAt = signedAt;
  }
}
