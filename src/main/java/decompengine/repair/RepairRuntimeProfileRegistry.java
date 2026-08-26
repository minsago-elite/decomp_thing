package decompengine.repair;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;

/** Immutable application-owned profile registry. There is intentionally no public registration. */
final class RepairRuntimeProfileRegistry {
    private static final Pattern PROFILE_ID = Pattern.compile("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}");

    private final NavigableMap<String, ResolvedProfile> profilesById;

    private RepairRuntimeProfileRegistry(NavigableMap<String, ResolvedProfile> profilesById) {
        this.profilesById = Collections.unmodifiableNavigableMap(new TreeMap<>(profilesById));
    }

    /** Deterministic package-owned construction seam used by production discovery and tests. */
    static RepairRuntimeProfileRegistry fromProviders(
        Iterable<? extends RepairRuntimeProfileProvider> providers
    ) {
        Objects.requireNonNull(providers, "providers");
        TreeMap<String, ResolvedProfile> resolved = new TreeMap<>();
        for (RepairRuntimeProfileProvider providerCandidate : providers) {
            RepairRuntimeProfileProvider provider = Objects.requireNonNull(
                providerCandidate,
                "repair profile provider"
            );
            String id = requireProfileId(provider.profileId(), "provider profile ID");
            if (resolved.containsKey(id)) {
                throw new IllegalStateException("duplicate repair profile provider ID: " + id);
            }

            RepairIndexProfile indexProfile = Objects.requireNonNull(
                provider.indexProfile(),
                "repair profile provider returned a null index profile for " + id
            );
            String indexId = requireProfileId(indexProfile.profileId(), "index profile ID");
            if (!id.equals(indexId)) {
                throw new IllegalStateException(
                    "repair provider ID does not exactly match its index profile ID: " + id
                );
            }
            resolved.put(id, new ResolvedProfile(id, indexProfile, provider));
        }
        return new RepairRuntimeProfileRegistry(resolved);
    }

    ResolvedProfile requireProfile(String profileId) {
        Objects.requireNonNull(profileId, "profileId");
        ResolvedProfile resolved = profilesById.get(profileId);
        if (resolved == null) {
            throw new IllegalArgumentException("unsupported registered repair profile: " + profileId);
        }
        return resolved;
    }

    Set<String> profileIds() {
        return Collections.unmodifiableSet(new LinkedHashSet<>(profilesById.navigableKeySet()));
    }

    private static String requireProfileId(String candidate, String description) {
        String id = Objects.requireNonNull(candidate, description);
        if (!PROFILE_ID.matcher(id).matches()) {
            throw new IllegalStateException("invalid " + description);
        }
        return id;
    }

    /** Fully validated immutable entry; only validation capability creation remains lazy. */
    static final class ResolvedProfile {
        private final String id;
        private final RepairIndexProfile indexProfile;
        private final RepairRuntimeProfileProvider provider;

        private ResolvedProfile(
            String id,
            RepairIndexProfile indexProfile,
            RepairRuntimeProfileProvider provider
        ) {
            this.id = id;
            this.indexProfile = indexProfile;
            this.provider = provider;
        }

        String id() {
            return id;
        }

        RepairIndexProfile indexProfile() {
            return indexProfile;
        }

        RepairValidationStrategy createValidationStrategy() {
            return Objects.requireNonNull(
                provider.createValidationStrategy(),
                "repair profile provider returned a null validation strategy for " + id
            );
        }
    }
}
