pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        mavenCentral()
    }
}

rootProject.name = "llm-bin-patch"
include("ghidra-bridge")

// Actions stores only allowed compiler task outputs here, separate from its
// dependency cache. Gradle still fingerprints every task input before reuse.
if (providers.environmentVariable("DECOMP_CI_COMPILER_CACHE").orNull == "1") {
    buildCache {
        local {
            directory = settingsDir.resolve("build/ci-compiler-cache")
        }
    }
}
