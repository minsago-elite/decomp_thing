package decompengine.repair;

import decompengine.agent.AgentHarness;

import java.nio.file.Path;
import java.util.Map;
import java.util.Objects;
import java.util.ServiceLoader;

/**
 * Verifier-enforced construction gate for production repair sessions.
 *
 * <p>The identity is never returned, accepted by this public facade, or stored in a caller-visible
 * object. This class owns every legitimate call that carries it into a Kotlin bridge. The bridges
 * independently compare reference identity before inspecting any caller-supplied component.
 * Candidate and repair-agent code is data handled by bounded transports/contained processes; it is
 * never loaded into this JVM. Reflection, Instrumentation, Unsafe, or equivalent access in the
 * trusted host process is therefore a host compromise and outside the candidate threat model.</p>
 */
public final class SecureRepairRuntime {
    private static final Object RUNTIME_IDENTITY = new Object();
    private static final ThreadLocal<ConstructionKind> CONSTRUCTION = new ThreadLocal<>();
    private static final RepairRuntimeProfileRegistry PROFILE_REGISTRY =
        RepairRuntimeProfileRegistry.fromProviders(
            ServiceLoader.load(
                RepairRuntimeProfileProvider.class,
                SecureRepairRuntime.class.getClassLoader()
            )
        );

    private SecureRepairRuntime() {
        throw new AssertionError("no instances");
    }

    /** Opens the sole production repair facade from immutable data-only configuration. */
    public static SecureRepairSession open(RepairRuntimeConfiguration configuration) {
        Objects.requireNonNull(configuration, "configuration");
        RepairRuntimeProfileRegistry.ResolvedProfile resolved =
            PROFILE_REGISTRY.requireProfile(configuration.getProfileId());
        RepairValidationStrategy validation = resolved.createValidationStrategy();

        // Capability availability and containment assurance fail before environment access,
        // history construction, graph mutation, transport construction, or agent execution.
        validation.requireAvailable();
        if (validation.getAssurance() != RepairValidationAssurance.STRICT_CONTAINED) {
            throw new SecurityException(
                "public repair execution requires a strict contained validation strategy"
            );
        }
        RegisteredProfile profile = new RegisteredProfile(
            resolved.id(),
            resolved.indexProfile()
        );

        HttpOpenAiCompatibleRepairClient client = HttpOpenAiCompatibleRepairClient.Companion.fromEnvironment(
            Map.copyOf(System.getenv())
        );
        AgentHarness harness = new RepairClientAgentHarness(client);
        RepairHistory history = new RepairHistory(
            configuration.getHistoryPath(),
            configuration.getResourceBudget().getMaximumProjectionBytes()
        );
        TraceGuidedRepairLoop loop = TraceGuidedRepairLoop.Companion.openAuthorized(
            RUNTIME_IDENTITY,
            harness,
            history,
            profile,
            validation,
            CapturedRepairStagingAuthority.INSTANCE,
            null,
            null,
            null,
            configuration.getResourceBudget(),
            false
        );
        return new SecureRepairSession(loop);
    }

    /** Package-owned graph acquisition; callers cannot construct a {@link RegisteredProfile}. */
    static ModuleRevisionGraph openGraph(
        Object profileHandle,
        Path projectRoot,
        RepairResourceBudget budget
    ) {
        RegisteredProfile profile = requireKnownHandle(profileHandle);
        GraphAuthority graphAuthority = new GraphAuthority(profile.profile);
        return ModuleRevisionGraph.Companion.openAuthorized(
            RUNTIME_IDENTITY,
            graphAuthority,
            projectRoot,
            profile.profile,
            budget,
            null
        );
    }

    /** Graph-owned index construction; the index never exists outside an authenticated graph. */
    static ModuleRepairIndex loadIndex(
        Object authorityCandidate,
        Path projectRoot,
        RepairIndexProfile profile,
        RepairResourceBudget budget
    ) {
        GraphAuthority authority = checkedGraphAuthority(authorityCandidate);
        if (authority.profile != profile) {
            throw new SecurityException("repair graph attempted to replace its registered profile");
        }
        return ModuleRepairIndex.Companion.loadAuthorized(
            RUNTIME_IDENTITY,
            authority,
            projectRoot,
            profile,
            budget
        );
    }

    /** Identity comparison used by each JVM-visible Kotlin bridge before it touches inputs. */
    static void requireRuntimeIdentity(Object candidate) {
        if (candidate != RUNTIME_IDENTITY) {
            throw new SecurityException("repair runtime authority is not available to this caller");
        }
    }

    static void authorizeLoopConstruction(Object profileHandle) {
        requireKnownHandle(profileHandle);
        armConstruction(ConstructionKind.LOOP);
    }

    static void authorizeGraphConstruction(Object graphAuthority) {
        checkedGraphAuthority(graphAuthority);
        armConstruction(ConstructionKind.GRAPH);
    }

    static void authorizeIndexConstruction(Object graphAuthority) {
        checkedGraphAuthority(graphAuthority);
        armConstruction(ConstructionKind.INDEX);
    }

    static void consumeLoopConstruction() {
        consumeConstruction(ConstructionKind.LOOP);
    }

    static void consumeGraphConstruction() {
        consumeConstruction(ConstructionKind.GRAPH);
    }

    static void consumeIndexConstruction() {
        consumeConstruction(ConstructionKind.INDEX);
    }

    static void clearConstructionAuthorization() {
        CONSTRUCTION.remove();
    }

    private static void armConstruction(ConstructionKind kind) {
        if (CONSTRUCTION.get() != null) {
            throw new SecurityException("nested repair construction authorization is forbidden");
        }
        CONSTRUCTION.set(kind);
    }

    private static void consumeConstruction(ConstructionKind expected) {
        ConstructionKind observed = CONSTRUCTION.get();
        CONSTRUCTION.remove();
        if (observed != expected) {
            throw new SecurityException("repair implementation constructor was invoked without its Java gate");
        }
    }

    private static RegisteredProfile requireKnownHandle(Object candidate) {
        if (!(candidate instanceof RegisteredProfile profile) || profile.issuer != RUNTIME_IDENTITY) {
            throw new SecurityException("repair profile handle was not issued by the production registry");
        }
        return profile;
    }

    static void requireGraphAuthority(Object candidate) {
        checkedGraphAuthority(candidate);
    }

    private static GraphAuthority checkedGraphAuthority(Object candidate) {
        if (!(candidate instanceof GraphAuthority authority) || authority.issuer != RUNTIME_IDENTITY) {
            throw new SecurityException("repair graph authority was not issued by the production gate");
        }
        return authority;
    }

    /**
     * Unforgeable profile handle. Its constructor and fields are private and no public API returns
     * it; only an already-authorized loop retains a registry-issued instance.
     */
    private static final class RegisteredProfile {
        private final Object issuer;
        private final String id;
        private final RepairIndexProfile profile;

        private RegisteredProfile(String id, RepairIndexProfile profile) {
            this.issuer = RUNTIME_IDENTITY;
            this.id = Objects.requireNonNull(id, "id");
            this.profile = Objects.requireNonNull(profile, "profile");
        }
    }

    private static final class GraphAuthority {
        private final Object issuer;
        private final RepairIndexProfile profile;

        private GraphAuthority(RepairIndexProfile profile) {
            this.issuer = RUNTIME_IDENTITY;
            this.profile = Objects.requireNonNull(profile, "profile");
        }
    }

    private enum ConstructionKind { LOOP, GRAPH, INDEX }
}
