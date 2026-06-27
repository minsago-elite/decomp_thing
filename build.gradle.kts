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
    testImplementation(kotlin("test"))
}
