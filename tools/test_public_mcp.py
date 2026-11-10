"""Actual SDK client, distinct stdio server process, exact CLI/API/MCP parity."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"runtime"))
from candidate import i7_api


async def run(output):
    output.mkdir(parents=True, exist_ok=False)
    report_root = output/"reports públicos"
    service = i7_api.public_profile(output_root=report_root)
    trace = []
    params = StdioServerParameters(command=sys.executable,
        args=["-m", "pg_i7_mcp.server", "--profile", "public", "--output-root", str(report_root)],
        cwd=str(ROOT), env={"PYTHONDONTWRITEBYTECODE": "1"})

    async def call(session, name, args, error=False):
        result = await session.call_tool(name, args)
        trace.append({"operation": name, "arguments": args, "result": result.model_dump(mode="json", by_alias=True)})
        assert bool(result.is_error) == error, str(result)
        if not error:
            assert result.structured_content is not None
        return result.structured_content

    with (output/"stderr.log").open("w", encoding="utf-8") as err:
        async with stdio_client(params, errlog=err) as (reader, writer):
            async with ClientSession(reader, writer, read_timeout_seconds=20) as session:
                initialized = await session.initialize()
                trace.append({"initialize": initialized.model_dump(mode="json", by_alias=True)})
                tools = await session.list_tools()
                trace.append({"tools": tools.model_dump(mode="json", by_alias=True)})
                assert {t.name for t in tools.tools} == {"availability", "catalog", "query", "verify", "generate", "read"}
                assert all(t.output_schema is not None for t in tools.tools)
                assert next(t for t in tools.tools if t.name == "generate").annotations.read_only_hint is False
                await call(session, "availability", {})
                await call(session, "catalog", {})
                query = await call(session, "query", {"package_id": "RUN012_PUBLIC"})
                assert query == service.query("RUN012_PUBLIC")
                receipt = await call(session, "verify", {"package_id": "RUN012_PUBLIC"})
                assert receipt == service.verify("RUN012_PUBLIC")
                args = {"package_id": "RUN012_PUBLIC", "receipt_id": receipt["receipt_id"], "request_key": "sdk-parity-001"}
                generated = await call(session, "generate", args)
                cli = subprocess.run([sys.executable, str(ROOT/"runtime/candidate/pg_i7.py"), "--profile", "public",
                                      "--output-root", str(report_root), "--json", "generate", "RUN012_PUBLIC", receipt["receipt_id"], "sdk-parity-001"],
                                     capture_output=True, text=True, timeout=20)
                assert cli.returncode == 0, cli.stderr
                assert json.loads(cli.stdout) == generated == service.generate(**args)
                report = await call(session, "read", {"report_id": generated["report_id"], "artifact": "REPORT.json", "limit": 16000})
                assert report == service.read(generated["report_id"], "REPORT.json", limit=16000)
                offset, parts = 0, []
                while True:
                    page = await call(session, "read", {"report_id": generated["report_id"], "offset": offset, "limit": 16000})
                    parts.append(page["content"])
                    if page["next_offset"] is None:
                        break
                    offset = page["next_offset"]
                assert "".join(parts) == (report_root/generated["report_id"]/"FINAL_HANDOFF.md").read_text("utf-8")
                await call(session, "query", {"package_id": "../secret"}, error=True)
                await call(session, "verify", {"package_id": "RUN012_PUBLIC", "verdict": "PASS"}, error=True)
                await call(session, "catalog", {"offset": "0"}, error=True)
                await call(session, "read", {"report_id": generated["report_id"], "artifact": "REQUEST.json"}, error=True)
        # Reconnect a fresh server and recover the same artifact.
        async with stdio_client(params, errlog=err) as (reader, writer):
            async with ClientSession(reader, writer, read_timeout_seconds=20) as session:
                await session.initialize()
                assert await call(session, "generate", args) == generated
    (output/"MCP_TRACE.json").write_text(json.dumps(trace, indent=2, ensure_ascii=True)+"\n", encoding="utf-8")
    result = {"MCP_SERVER_E2E": "PASS", "CLI_MCP_PARITY": "PASS", "excluded_ephemeral_fields": [],
              "CODEX_MCP_E2E": "NOT_EXECUTED_BY_THIS_TEST", "report": generated,
              "process_boundary": "SDK client and stdio server are distinct processes"}
    (output/"RESULT.json").write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
    print(json.dumps(result))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    asyncio.run(run(parser.parse_args().output))
