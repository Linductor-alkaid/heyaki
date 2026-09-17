# NOTICE: libnice and GLib (LGPL-2.1) system dependencies

This notice applies to Heyaki release artifacts built with
`HEYAKI_ICE_BACKEND=nice` (the TURN/TCP-capable Linux build).

Those builds link the system `libnice` and `glib-2.0` libraries dynamically.
Both are licensed under the GNU Lesser General Public License 2.1 or later
(the full text ships beside this file as `lgpl-2.1.txt`).

Dynamic linking satisfies the LGPL's relinking obligation: recipients can
relink the Heyaki binaries against a modified or newer libnice/GLib by
providing compatible shared libraries on the target system (standard
`LD_LIBRARY_PATH`/ldconfig resolution; the binaries do not statically embed
libnice or GLib code).

To comply with LGPL section 4 alternatives when redistributing:

- Include this notice and `lgpl-2.1.txt` with the distribution (the release
  tarball does; the install tree carries both under
  `share/heyaki/licenses/`).
- The corresponding source is the system distribution's source package for
  `libnice` / `glib2.0`, or upstream:
  - libnice: https://gitlab.freedesktop.org/libnice/libnice
  - GLib: https://gitlab.gnome.org/GNOME/glib
- The Heyaki build probes libnice with the pinned dependency's own find
  modules; the accepted version floor (0.1.21) is recorded in
  `docs/supply-chain/dependency-policy.md`.

Release builds made with the default `juice` backend do not link libnice or
GLib, and this notice does not apply to them.
