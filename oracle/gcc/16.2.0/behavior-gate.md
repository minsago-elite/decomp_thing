# GCC driver behavior gate record

This record is the bounded status of the GCC metadata and diagnostic gate for
issue [#51](https://github.com/minsago-elite/decomp_thing/issues/51). It is
retained with the versioned GCC profile so a reference pass cannot be mistaken
for reconstructed-candidate equivalence.

## Reference identity

The checked reference corpus is `gcc-16-2-0-driver-behavior`.

| Record | SHA-256 |
| --- | --- |
| `source-lock.json` | `e2930ecc9748b40e56d6fe09dbe88f21f735953d4e6da50403f2cc0aa5b650cc` |
| `oracle-manifest.json` | `c9e21c5a6422c65572ee4c4de5578107b82ae92b6730536c4fc76490fe2ecad9` |
| `build-record.json` | `f91a68ffde054b9598cba8506bbf6b3b373b35b8680fddb54f76bffa9db23637` |
| `behavior-corpus.json` | `bcc1a14ca8c54f94106c943f0bc5698cb9af3151b7bf20a49ae3c8828baaad0e` |
| `behavior-corpus-evidence.json` | `9dcf787aea232615a1ff8721144b86bc1f5e9a2a7068fa9e9280db0bc4ad6803` |
| authenticated stripped driver | `3c0cfef73a02b06b40456e89d9d9e33727144c2f473b8b7256b361a7699d48a4` |

The retained evidence reports 14/14 reference cases passed. Its cases cover
version, target, help, one `COMPILER_PATH` search-path observation, an
unsupported option, missing input, and the surrounding preprocessing,
compilation, assembly, linking, and response-file cases. Every checked stream
has an empty normalization list; no identity substitution is authorized by
this record.

## Gate state

The reference gate is **available as retained evidence**. The reconstructed
candidate gate is **unavailable and unresolved**:

- #50 has not supplied an authenticated accepted reconstruction archive and
  exact candidate executable for this comparison.
- The retained evidence is bound to the oracle's stripped driver, so it cannot
  be presented as candidate execution or runtime equivalence.
- The mandatory inventory still lacks a distinct search-directory metadata
  query and a malformed-input diagnostic case. The existing search-path case
  observes `COMPILER_PATH`; it does not establish a complete search-directory
  query inventory. The existing invalid-option case is the retained
  unsupported-option observation; no broader option-validation matrix is
  claimed.
- Until an authenticated candidate run supplies every required case's exit,
  normalized stdout, and normalized stderr under the pinned environment, the
  behavior result is **unresolved** and `releaseEligible` remains **false**.

This record does not authorize a reference-only pass, caller-supplied output,
or a substituted executable to close #51. A future candidate receipt must bind
the candidate source/build/archive identity, executable identity, pinned
executor identity, exact case IDs, observed bytes, and any narrowly justified
field-level normalization before comparison or release use.
