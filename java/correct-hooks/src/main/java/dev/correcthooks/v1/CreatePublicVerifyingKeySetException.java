package dev.correcthooks.v1;

/** Errors that can be thrown from {@link CorrectHooks#createPublicVerifyingKeySet}. */
public class CreatePublicVerifyingKeySetException extends Exception {
  private static final long serialVersionUID = 1L;

  /** The possible kinds of a {@link CreatePublicVerifyingKeySetException}. */
  public enum Kind {
    INVALID_KEY_FOUND
  }

  private final Kind kind;

  public CreatePublicVerifyingKeySetException(Kind kind) {
    super(kind.name());
    this.kind = kind;
  }

  public CreatePublicVerifyingKeySetException(Kind kind, Throwable cause) {
    super(kind.name(), cause);
    this.kind = kind;
  }

  public Kind getKind() {
    return kind;
  }
}
