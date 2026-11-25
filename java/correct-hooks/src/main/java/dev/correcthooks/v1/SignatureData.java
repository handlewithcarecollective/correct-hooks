package dev.correcthooks.v1;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/**
 * Header values to set on the webhook request.
 *
 * <p>You must set the request headers {@code correct-hooks-signature-components} and {@code
 * correct-hooks-signature} to these values. Webhook consumers will pass the values of the headers
 * to the verify function. Future versions of Correct Hooks with convenience functions that verify
 * specific framework's request objects will expect these exact header names to be set.
 */
public final class SignatureData {
  /** Set the header {@code correct-hooks-signature-components} to this value. */
  public final String correctHooksSignatureComponents;

  /** Set the header {@code correct-hooks-signature} to this value. */
  public final String correctHooksSignature;

  @JsonCreator
  public SignatureData(
      @JsonProperty(value = "correctHooksSignatureComponents", required = true)
          String correctHooksSignatureComponents,
      @JsonProperty(value = "correctHooksSignature", required = true)
          String correctHooksSignature) {
    this.correctHooksSignatureComponents = correctHooksSignatureComponents;
    this.correctHooksSignature = correctHooksSignature;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof SignatureData)) {
      return false;
    }
    SignatureData other = (SignatureData) o;
    return correctHooksSignatureComponents.equals(other.correctHooksSignatureComponents)
        && correctHooksSignature.equals(other.correctHooksSignature);
  }

  @Override
  public int hashCode() {
    return Objects.hash(correctHooksSignatureComponents, correctHooksSignature);
  }
}
