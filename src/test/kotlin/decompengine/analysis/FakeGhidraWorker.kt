package decompengine.analysis

import java.nio.file.Path

internal fun fakeGhidraCommand(executable: Path): (GhidraInvocation) -> List<String> = { invocation ->
    listOf(
        executable.toString(), invocation.project.toAbsolutePath().toString(), invocation.projectName,
        "-import", invocation.input.toAbsolutePath().toString(), "-overwrite",
        "-scriptPath", invocation.scripts.toAbsolutePath().toString(),
    ) + invocation.postScripts.flatMap { listOf("-postScript", it.name) + it.arguments }
}
