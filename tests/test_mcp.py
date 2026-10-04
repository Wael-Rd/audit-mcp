import asyncio

from mcp import Client

from aegis_mcp.server import create_server


def test_real_mcp_tools_resources_prompts_and_report_flow(engine):
    async def run():
        async with Client(create_server(engine), raise_exceptions=True) as client:
            tools = await client.list_tools()
            names = {tool.name for tool in tools.tools}
            assert {"audit_target", "get_hardening_guide", "create_hardening_plan", "render_report"} <= names
            guide = await client.call_tool("get_hardening_guide")
            assert len(guide.structured_content["steps"]) == 10
            resources = await client.list_resources()
            assert len(resources.resources) == 4
            prompts = await client.list_prompts()
            assert {p.name for p in prompts.prompts} == {"confidentiality_audit", "professional_report"}
            audit = await client.call_tool("audit_target", {"target_id": "test"})
            identifier = audit.structured_content["audit_id"]
            context = await client.call_tool("get_report_context", {"audit_id": identifier})
            assert len(context.structured_content["sections"]) == 10
            report = await client.call_tool(
                "render_report",
                {
                    "audit_id": identifier,
                    "narrative": {
                        "title": "Evidence, with clarity.",
                        "executive_summary": "Observed facts only.",
                    },
                },
            )
            assert report.structured_content["status"] == "exported"

    asyncio.run(run())
