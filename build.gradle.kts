plugins {
    kotlin("jvm") version "2.4.0"
    application
}

group = "dev.decompengine"
version = "0.1.0"

kotlin {
    jvmToolchain(21)
}

application {
    mainClass.set("decompengine.MainKt")
    applicationName = "llm_bin_patch"
}

tasks.test {
    useJUnitPlatform()
    environment(
        "DECOMP_ACP_PARENT_SECRET_CANARY",
        "decomp-acp-parent-secret-canary-must-not-cross-the-sandbox",
    )
}

dependencies {
    implementation("com.agentclientprotocol:acp:0.30.1")
    implementation("net.java.dev.jna:jna:5.19.1")
    runtimeOnly("org.slf4j:slf4j-nop:2.0.16")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.9.0")
    testImplementation(kotlin("test"))
}
