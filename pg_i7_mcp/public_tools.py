"""Six bounded operations registered on the existing MCP transport/validation path."""
from typing import Annotated, Literal, Any

from mcp_types import ToolAnnotations
from pydantic import Field

Opaque = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$")]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Offset = Annotated[int, Field(ge=0, le=262144)]
Page = Annotated[int, Field(ge=1, le=16000)]


def register(server, service):
    engineering = getattr(service, "profile", "") == "engineering-local-v1"
    evidence = getattr(service, "profile", "") == "evidence-local-v1"
    readonly = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False)
    writing = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False)

    @server.tool(annotations=readonly, description=("Discover bounded static analysis and persistent evidence capabilities under this local manifest." if evidence else "Discover approved engineering projections, registered sources and exact limits. No historical execution or final authority." if engineering else "Discover public aggregate profile, registered sources, capabilities and exact limits. No historical execution or final authority."))
    def availability() -> dict[str, Any]:
        return service.availability()

    @server.tool(annotations=readonly, description=("List registered engineering packages and synthetic markers with explicit pagination. Does not register sources." if engineering else "List registered public packages, with explicit pagination. Does not register sources."))
    def catalog(offset: Offset = 0, limit: Annotated[int, Field(ge=1, le=20)] = 10) -> dict[str, Any]:
        return service.catalog(offset, limit)

    @server.tool(annotations=writing if evidence else readonly, description=("Consult registered per-source properties and persistent synthetic evidence; no code execution or raw source exposure." if evidence else "Consult approved engineering scalars with selectors/hashes, current coverage and limits. Private bodies withheld; no original tests or semantic regrade." if engineering else "Consult one public package: historical declarations with selectors/hashes, current coverage and limits. No original tests or semantic regrade."))
    def query(package_id: Opaque) -> dict[str, Any]:
        return service.query(package_id)

    @server.tool(annotations=writing if evidence else readonly, description=("Verify selected source identities, explicit relations or static properties; initializes derived local memory when needed. No global code verdict." if evidence else "Verify registered engineering bytes and explicit scalar relations; obtain snapshot-bound receipt_id. Domain FAIL/PARTIAL remains a successful tool result." if engineering else "Verify registered aggregate bytes and count consistency; obtain snapshot-bound receipt_id. Domain FAIL/PARTIAL remains a successful tool result."))
    def verify(package_id: Opaque) -> dict[str, Any]:
        return service.verify(package_id)

    @server.tool(annotations=writing, description="Generate new factual REPORT.json/FINAL_HANDOFF.md/MANIFEST.json in bound output root. Requires current receipt_id; same request_key is idempotent. Writes derived artifacts, never changes historical verdicts.")
    def generate(package_id: Opaque, receipt_id: Digest, request_key: Opaque) -> dict[str, Any]:
        return service.generate(package_id, receipt_id, request_key)

    @server.tool(annotations=readonly, description="Retrieve generated report artifact with verified hashes and explicit character pagination. Follow next_offset until null for full content.")
    def read(report_id: Opaque, artifact: Literal["FINAL_HANDOFF.md", "REPORT.json", "MANIFEST.json"] = "FINAL_HANDOFF.md",
             offset: Offset = 0, limit: Page = 8000) -> dict[str, Any]:
        return service.read(report_id, artifact, offset, limit)
