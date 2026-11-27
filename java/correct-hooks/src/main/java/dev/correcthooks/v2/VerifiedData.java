package dev.correcthooks.v2;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.UUID;

/** Validated request data. */
public final class VerifiedData {
  /**
   * The validated {@code webhookId} for the request. These id's can be put in a shared cache by the
   * webhook consumer and checked against for the highest level of replay protection.
   */
  public final UUID webhookId;

  @JsonCreator
  public VerifiedData(@JsonProperty(value = "webhookId", required = true) UUID webhookId) {
    this.webhookId = webhookId;
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof VerifiedData && webhookId.equals(((VerifiedData) o).webhookId);
  }

  @Override
  public int hashCode() {
    return webhookId.hashCode();
  }
}
