"""Version 1 migration API for complete source audit publication operations.

No caller-supplied reports, verification bodies or custody sessions are accepted.
The existing V2 artifact schemas and CLI acknowledgement semantics are preserved.
"""
import argparse
from pathlib import Path

from tools import audit_source_v2, verify_source_v2


def publish_audit_v1(source_root, catalog_path, catalog_sha256, output):
    """Return (report, manifest) only after fresh capture/publication and close.

    Raises on failure; an existing destination is never replaced or resumed.
    A returned report is a historical observation, not freshness at ACK.
    """
    return audit_source_v2.audit_and_write(source_root, catalog_path,
                                         catalog_sha256, output)


def publish_verification_v1(source_root, artifacts, output):
    """Reopen and verify artifacts, publish to a new file, print the result.

    Return the existing verifier exit code (0 PASS, 1 failure). A file may exist
    after failure; file existence is never an acknowledgement. This entry point
    intentionally requires artifact input and output rather than a supplied body.
    """
    # Validate raw arguments before Path can normalize unsafe Windows components.
    source_root, artifacts, output = (
        verify_source_v2.cli_path(value) for value in (source_root, artifacts, output))
    return verify_source_v2.execute(argparse.Namespace(
        source_root=Path(source_root), artifacts=Path(artifacts), output=Path(output),
        report=None, pages=None))
