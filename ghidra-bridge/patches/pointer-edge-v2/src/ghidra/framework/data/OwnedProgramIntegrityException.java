package ghidra.framework.data;

/** Sticky owned dependency failure; only the domain-object receipt creates it. */
public final class OwnedProgramIntegrityException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    OwnedProgramIntegrityException(Throwable cause) { super("Owned program integrity failure", cause); }
}
