#!/usr/bin/env python3
"""Apply file-write limits before the existing sanitizer invocation and timeout."""

import os
import resource
import signal
import sys


MAX_OUTPUT_BYTES = 1048576
WALL_LIMIT = "10s"
KILL_GRACE = "1s"
LIMIT_FAILURE = 125


def main(arguments=None):
    arguments = sys.argv[1:] if arguments is None else arguments
    try:
        if (len(arguments) != 1 or not os.path.isabs(arguments[0])
                or "\0" in arguments[0]):
            raise ValueError("one absolute fixture executable is required")
        # One sentinel byte distinguishes overflow from exactly the accepted limit.
        # Refuse a lower inherited limit rather than raising it or hiding exhaustion.
        ceiling = MAX_OUTPUT_BYTES + 1
        inherited = resource.getrlimit(resource.RLIMIT_FSIZE)
        if any(n != resource.RLIM_INFINITY and n < ceiling for n in inherited):
            raise ValueError("inherited write limit cannot supply the diagnostic budget")
        resource.setrlimit(resource.RLIMIT_FSIZE, (ceiling, ceiling))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        signal.signal(signal.SIGXFSZ, signal.SIG_DFL)
        # The same limit applies to timeout and its child, including tool diagnostics.
        os.execvp("timeout", ["timeout", "--signal=TERM", "--kill-after=" + KILL_GRACE,
                              WALL_LIMIT, arguments[0]])
    except (OSError, ValueError):
        try:
            os.write(2, b"Clang sanitizer bounds could not be established\n")
        except OSError:
            pass  # Even a zero inherited write budget must retain the failure status.
        return LIMIT_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())
