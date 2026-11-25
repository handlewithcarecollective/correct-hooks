package dev.correcthooks.v1;

/** Errors thrown by the {@link CorrectHooks#sign} function. */
public class SignException extends Exception {
  private static final long serialVersionUID = 1L;

  /** The possible kinds of a {@link SignException}. */
  public enum Kind {
    INVALID_ARGS,
    INVALID_SIGNING_KEY
  }

  private final Kind kind;

  public SignException(Kind kind) {
    super(kind.name());
    this.kind = kind;
  }

  public SignException(Kind kind, Throwable cause) {
    super(kind.name(), cause);
    this.kind = kind;
  }

  public Kind getKind() {
    return kind;
  }
}
