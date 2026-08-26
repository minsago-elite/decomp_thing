package decompengine.repair;

/**
 * Application-owned provider for one production repair profile.
 *
 * <p>Providers are discovered only from the class loader that defines {@link SecureRepairRuntime}.
 * That loader and its service metadata are trusted host configuration; candidate code is never
 * loaded into it. The public runtime accepts only the provider's stable data-only ID and exposes no
 * registration API.</p>
 */
public interface RepairRuntimeProfileProvider {
    /** Stable, exact ID accepted by {@link RepairRuntimeConfiguration}. */
    String profileId();

    /** Program/build-specific indexing adapter for this ID. */
    RepairIndexProfile indexProfile();

    /**
     * Creates the validation capability for a selected session.
     *
     * <p>This is deliberately lazy: an unavailable unrelated profile must not prevent a different
     * registered profile from being selected.</p>
     */
    RepairValidationStrategy createValidationStrategy();
}
