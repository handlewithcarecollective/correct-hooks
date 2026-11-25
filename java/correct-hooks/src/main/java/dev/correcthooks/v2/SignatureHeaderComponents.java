package dev.correcthooks.v2;

import java.util.UUID;

/**
 * This class is only public for internal testing purposes and will be made private in a future
 * version of this library.
 */
public final class SignatureHeaderComponents {
  public final UUID webhookId;
  public final UUID keyId;
  public final long signedAt;
  public final byte[] signature;

  public SignatureHeaderComponents(UUID webhookId, UUID keyId, long signedAt, byte[] signature) {
    this.webhookId = webhookId;
    this.keyId = keyId;
    this.signedAt = signedAt;
    this.signature = signature;
  }
}
