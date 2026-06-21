"""Cernis benchmark public-release tooling (phase-bench-3).

Two pieces, in dependency order:

  - `scrub`           privacy/secret scan + consent coverage filter.
                       Hard-blocks release on any PII / secret leak;
                       drops sessions whose consent doesn't cover
                       public release.
  - `build_release`   assembles the release directory, runs the scrub
                       gate, computes the manifest + tarball + sha256.

`build_release` will not start packaging until `scrub` has signed off
on the candidate file set. See `benchmark/release/templates/` for the
human-facing docs (DATASHEET / TASK / README / licenses) that ship
inside every release.
"""
