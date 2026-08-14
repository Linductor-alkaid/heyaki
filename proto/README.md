# Protocol Sources

Heyaki protocol schemas are versioned below `proto/heyaki/<domain>/v1`. Every schema uses
the Protobuf Lite runtime. The source schema is authoritative; checked-in generated C++ is
not allowed.

When code generation is enabled by a consuming milestone, generated files must be written to
`HEYAKI_GENERATED_DIR`, which CMake requires to remain inside the build tree. Imports resolve
from this `proto/` directory.
