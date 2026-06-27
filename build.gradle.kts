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
}

tasks.test {
    useJUnitPlatform()
}

dependencies {
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.9.0")
    testImplementation(kotlin("test"))
}

tasks.register<JavaExec>("roadmapCheck") {
    group = "verification"
    description = "Validate roadmap state."
    classpath = sourceSets.main.get().runtimeClasspath
    mainClass.set("decompengine.MainKt")
    args("roadmap", "check")
}

tasks.register<JavaExec>("roadmapUpdate") {
    group = "documentation"
    description = "Regenerate roadmap summary and report files."
    classpath = sourceSets.main.get().runtimeClasspath
    mainClass.set("decompengine.MainKt")
    args("roadmap", "update")
}
