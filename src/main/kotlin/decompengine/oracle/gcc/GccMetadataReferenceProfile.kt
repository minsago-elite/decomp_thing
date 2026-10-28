package decompengine.oracle.gcc

import decompengine.oracle.reference.AuthenticatedReferenceCorpusProfile
import java.nio.file.Path

/** Fixed benchmark adapter; no caller-supplied corpus, digest, source revision or authority flag. */
internal object GccMetadataReferenceProfile {
    const val REGISTRATION_ID = "gcc-metadata-v1"

    fun open(profileRoot: Path): AuthenticatedReferenceCorpusProfile =
        AuthenticatedReferenceCorpusProfile.open(profileRoot, REGISTRATION_ID)
}
