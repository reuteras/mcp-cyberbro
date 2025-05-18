import asyncio
import os
import json
from typing import Any
from mcp.server.models import InitializationOptions
from mcp.server import NotificationOptions, Server
from pydantic import AnyUrl
import httpx
import argparse

import mcp.types as types
import mcp.server.stdio

ENGINES = [
    {
        "name": "reverse_dns",
        "label": "Reverse DNS",
        "supports": ["domain", "IP", "abuse"],
        "description": "Performs a reverse DNS lookup (local DNS) for IP, domain, URL (on the Cyberbro machine)"
    },
    {
        "name": "rdap",
        "label": "RDAP (ex Whois)",
        "supports": ["abuse", "domain"],
        "description": "Checks RDAP (ex Whois) record for domain, URL"
    },
    {
        "name": "ipquery",
        "label": "IPquery",
        "supports": ["IP", "risk", "VPN", "proxy", "geoloc"],
        "description": "Checks IPquery for IP, reversed obtained IP for a given domain/URL"
    },
    {
        "name": "abuseipdb",
        "label": "AbuseIPDB",
        "supports": ["risk", "IP"],
        "description": "Checks AbuseIPDB for IP, reversed obtained IP for a given domain/URL"
    },
    {
        "name": "ipinfo",
        "label": "IPinfo",
        "supports": ["IP", "geoloc"],
        "description": "Checks IPinfo for IP, reversed obtained IP for a given domain/URL"
    },
    {
        "name": "virustotal",
        "label": "VirusTotal",
        "supports": ["hash", "risk", "IP", "domain", "URL"],
        "description": "Checks VirusTotal for IP, domain, URL, hash"
    },
    {
        "name": "spur",
        "label": "Spur.us",
        "supports": ["VPN", "proxy", "IP"],
        "description": "Scraps Spur.us for IP, reversed obtained IP for a given domain/URL"
    },
    {
        "name": "mde",
        "label": "Microsoft Defender for Endpoint",
        "supports": ["hash", "IP", "domain", "URL"],
        "description": "Checks Microsoft Defender for Endpoint EDR API for IP, domain, URL, hash"
    },
    {
        "name": "crowdstrike",
        "label": "CrowdStrike",
        "supports": ["hash", "IP", "domain", "URL"],
        "description": "Checks CrowdStrike EDR for IP, domain, URL, hash using Falcon API"
    },
    {
        "name": "google_safe_browsing",
        "label": "Google Safe Browsing",
        "supports": ["risk", "domain", "IP", "URL"],
        "description": "Checks Google Safe Browsing for IP, domain, URL"
    },
    {
        "name": "shodan",
        "label": "Shodan",
        "supports": ["ports", "IP"],
        "description": "Checks Shodan, reversed obtained IP for a given domain/URL"
    },
    {
        "name": "phishtank",
        "label": "Phishtank",
        "supports": ["risk", "domain", "URL"],
        "description": "Checks Phishtank for domains, URL"
    },
    {
        "name": "threatfox",
        "label": "ThreatFox",
        "supports": ["IP", "domain", "URL"],
        "description": "Checks ThreatFox by Abuse.ch for IP, domains, URL"
    },
    {
        "name": "urlscan",
        "label": "URLscan",
        "supports": ["domain", "URL", "IP", "hash"],
        "description": "Checks URLscan for all types of observable"
    },
    {
        "name": "google",
        "label": "Google",
        "supports": ["domain", "URL", "IP", "hash", "chrome_extension_id", "edge_extension_id"],
        "description": "Scraps Google search results for all types of observable"
    },
    {
        "name": "github",
        "label": "Github",
        "supports": ["domain", "URL", "IP", "hash", "chrome_extension_id", "edge_extension_id"],
        "description": "Get Github grep.app API search results for all types of observable"
    },
    {
        "name": "ioc_one_html",
        "label": "Ioc.One (HTML)",
        "supports": ["domain", "URL", "IP", "hash", "chrome_extension_id", "edge_extension_id"],
        "description": "Scraps (can be long) Ioc.One HTML search results for all types of observable"
    },
    {
        "name": "ioc_one_pdf",
        "label": "Ioc.One (PDF)",
        "supports": ["domain", "URL", "IP", "hash", "chrome_extension_id", "edge_extension_id"],
        "description": "Scraps (can be long) Ioc.One PDF search results for all types of observable"
    },
    {
        "name": "opencti",
        "label": "OpenCTI",
        "supports": ["domain", "URL", "IP", "hash"],
        "description": "Searches OpenCTI results for all types of observable"
    },
    {
        "name": "abusix",
        "label": "Abusix",
        "supports": ["abuse", "IP"],
        "description": "Checks abuse contact with Abusix for IP, reversed obtained IP for a given domain/URL"
    },
    {
        "name": "hudsonrock",
        "label": "Hudson Rock",
        "supports": ["domain", "URL", "email", "infostealers", "malware"],
        "description": "Searches Hudson Rocks results for domains, URL, Email"
    },
    {
        "name": "webscout",
        "label": "WebScout",
        "supports": ["IP", "risk", "geoloc", "VPN", "proxy"],
        "description": "Checks WebScout for IP, reversed obtained IP for a given domain / URL"
    },
    {
        "name": "criminalip",
        "label": "CriminalIP",
        "supports": ["IP", "risk", "VPN", "proxy"],
        "description": "Checks CriminalIP for IP, reversed obtained IP for a given domain / URL"
    },
    {
        "name": "alienvault",
        "label": "Alienvault",
        "supports": ["IP", "domain", "URL", "hash", "risk"],
        "description": "Checks Alienvault for IP, domain, URL, hash"
    },
    {
        "name": "misp",
        "label": "MISP",
        "supports": ["IP", "domain", "URL", "hash"],
        "description": "Checks MISP for IP, domain, URL, hash"
    },
    {
        "name": "google_dns",
        "label": "Google DNS (common records)",
        "supports": ["IP", "domain", "URL"],
        "description": "Checks Google common DNS records (A, AAAA, CNAME, NS, MX, TXT, PTR) for IP, domain, URL"
    }
]

server = Server("CyberbroMCP")

@server.list_resources()
async def handle_list_resources() -> list[types.Resource]:
    """
    List all available Cyberbro engines as resources.
    """
    return [
        types.Resource(
            uri=AnyUrl(f"cyberbro://engine/{engine['name']}"),
            name=engine["label"],
            description=engine["description"],
            mimeType="application/json",
        )
        for engine in ENGINES
    ]

@server.read_resource()
async def handle_read_resource(uri: AnyUrl) -> str:
    """
    Read a specific engine's details by its URI.
    """
    if uri.scheme != "cyberbro":
        raise ValueError(f"Unsupported URI scheme: {uri.scheme}")
    path_parts = uri.path.strip("/").split("/")
    if len(path_parts) != 2 or path_parts[0] != "engine":
        raise ValueError("Invalid resource path")
    engine_name = path_parts[1]
    for engine in ENGINES:
        if engine["name"] == engine_name:
            return json.dumps(engine, indent=2)
    return "{}"

@server.list_tools()
async def list_tools() -> list[types.Tool]:
    """
    List tools to interact with Cyberbro API.
    """
    return [
        types.Tool(
            name="analyze_observable",
            description="Trigger an analysis for a given observable (IP, domain, URL, hash, chrome extension id) using Cyberbro. It can support multiple observables at once separated by spaces.",
            inputSchema={
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Observable(s) to analyze"},
                    "engines": {"type": "array", "items": {"type": "string"}, "description": "List of engine names"}
                },
                "required": ["text", "engines"]
            }
        ),
        types.Tool(
            name="is_analysis_complete",
            description="Check if the analysis is complete for the given analysis_id.",
            inputSchema={
                "type": "object",
                "properties": {
                    "analysis_id": {"type": "string", "description": "Analysis ID to check"}
                },
                "required": ["analysis_id"]
            }
        ),
        types.Tool(
            name="get_analysis_results",
            description="Retrieve the results of a previous analysis by analysis_id.",
            inputSchema={
                "type": "object",
                "properties": {
                    "analysis_id": {"type": "string", "description": "Analysis ID to retrieve results for"}
                },
                "required": ["analysis_id"]
            }
        ),
        types.Tool(
            name="get_engines",
            description="List available Cyberbro engines.",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        )
    ]

@server.call_tool()
async def handle_call_tool(name: str, arguments: dict[str, Any] | None) -> list[types.TextContent]:
    """
    Handle tool execution requests for interacting with the Cyberbro API.
    """
    if arguments is None:
        arguments = {}

    async with httpx.AsyncClient() as client:
        try:
            if name == "analyze_observable":
                text = arguments.get("text")
                engines = arguments.get("engines")
                payload = {"text": text, "engines": engines}
                response = await client.post(f"{CYBERBRO_API}/analyze", json=payload)
                response.raise_for_status()
                return [types.TextContent(type="text", text=json.dumps(response.json(), indent=2))]

            elif name == "is_analysis_complete":
                analysis_id = arguments.get("analysis_id")
                response = await client.get(f"{CYBERBRO_API}/is_analysis_complete/{analysis_id}")
                response.raise_for_status()
                return [types.TextContent(type="text", text=json.dumps(response.json(), indent=2))]

            elif name == "get_analysis_results":
                analysis_id = arguments.get("analysis_id")
                response = await client.get(f"{CYBERBRO_API}/results/{analysis_id}")
                response.raise_for_status()
                return [types.TextContent(type="text", text=json.dumps(response.json(), indent=2))]

            elif name == "get_engines":
                return [types.TextContent(type="text", text=json.dumps({"engines": ENGINES}, indent=2))]

            else:
                raise ValueError(f"Unknown tool: {name}")

        except Exception as e:
            return [types.TextContent(type="text", text=f"Error executing {name}: {str(e)}")]

async def main():
    """Start the MCP server."""
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="cyberbro",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cyberbro MCP Server")
    parser.add_argument("--cyberbro_url", type=str, required=False, help="Base URL for Cyberbro API (env: CYBERBRO_URL)")
    parser.add_argument("--api_prefix", type=str, default=None, help="API prefix path (env: API_PREFIX, default: api)")
    args = parser.parse_args()

    CYBERBRO_URL = args.cyberbro_url or os.environ.get("CYBERBRO_URL")
    API_PREFIX = args.api_prefix or os.environ.get("API_PREFIX", "api")

    if not CYBERBRO_URL:
        raise ValueError("cyberbro_url must be provided as --cyberbro_url or CYBERBRO_URL env variable")

    CYBERBRO_API = CYBERBRO_URL.rstrip("/") + "/" + API_PREFIX.strip("/")
    asyncio.run(main())