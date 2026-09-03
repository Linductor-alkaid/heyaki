# Protocol Sources

Heyaki protocol schemas are versioned below `proto/heyaki/<domain>/v1`. Every schema uses
the Protobuf Lite runtime. The source schema is authoritative; checked-in generated C++ is
not allowed.

When code generation is enabled by a consuming milestone, generated files must be written to
`HEYAKI_GENERATED_DIR`, which CMake requires to remain inside the build tree. Imports resolve
from this `proto/` directory.

M1 validates the golden `MessageEnvelope` with the pinned Protobuf runtime's wire decoder, including
unknown-field and malformed-length behavior. The first milestone that consumes generated messages must
add its generated Lite decoder paths to the existing parser fuzz targets.

Protocol 1.1 adds `discovery/v1/discovery.proto` and `signaling/v1/lan.proto`. Their generated Lite
decoders are part of the parser fuzz target; LAN implementations must validate the fixed datagram and
field limits before retaining a decoded message.

The service domains (`message`, `rpc`, `event`, `file`, `shell`) ride hand-rolled codecs over the
shared minimal wire codec in production (`src/core/*_protocol.cpp`); their generated Lite decoders
exist only for the parser fuzz target. M8 (2026-09-03) added the shell frame family to the runtime:
`shell/v1/shell.proto` bodies plus the raw 28-byte `ShellData` header, with
`Limits::max_shell_data_bytes`/`max_shell_control_bytes` enforced in the wire layer.
