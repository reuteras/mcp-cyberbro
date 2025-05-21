import os
from typing import Any
import httpx
import argparse

from mcp.server.fastmcp import FastMCP

ENGINES = [
    {
        "name": "reverse_dns",
        "label": "Reverse DNS",
        "supports": ["domain", "IP", "abuse"],
        "description": "Performs a reverse DNS lookup (local DNS) for IP, domain, URL (on the Cyberbro machine)",
    },
    {
        "name": "rdap",
        "label": "RDAP (ex Whois)",
        "supports": ["abuse", "domain"],
        "description": "Checks RDAP (ex Whois) record for domain, URL",
    },
    {
        "name": "ipquery",
        "label": "IPquery",
        "supports": ["IP", "risk", "VPN", "proxy", "geoloc"],
        "description": "Checks IPquery for IP, reversed obtained IP for a given domain/URL",
    },
    {
        "name": "abuseipdb",
        "label": "AbuseIPDB",
        "supports": ["risk", "IP"],
        "description": "Checks AbuseIPDB for IP, reversed obtained IP for a given domain/URL",
    },
    {
        "name": "ipinfo",
        "label": "IPinfo",
        "supports": ["IP", "geoloc"],
        "description": "Checks IPinfo for IP, reversed obtained IP for a given domain/URL",
    },
    {
        "name": "virustotal",
        "label": "VirusTotal",
        "supports": ["hash", "risk", "IP", "domain", "URL"],
        "description": "Checks VirusTotal for IP, domain, URL, hash",
    },
    {
        "name": "spur",
        "label": "Spur.us",
        "supports": ["VPN", "proxy", "IP"],
        "description": "Scraps Spur.us for IP, reversed obtained IP for a given domain/URL",
    },
    {
        "name": "mde",
        "label": "Microsoft Defender for Endpoint",
        "supports": ["hash", "IP", "domain", "URL"],
        "description": "Checks Microsoft Defender for Endpoint EDR API for IP, domain, URL, hash",
    },
    {
        "name": "crowdstrike",
        "label": "CrowdStrike",
        "supports": ["hash", "IP", "domain", "URL"],
        "description": "Checks CrowdStrike EDR for IP, domain, URL, hash using Falcon API",
    },
    {
        "name": "google_safe_browsing",
        "label": "Google Safe Browsing",
        "supports": ["risk", "domain", "IP", "URL"],
        "description": "Checks Google Safe Browsing for IP, domain, URL",
    },
    {
        "name": "shodan",
        "label": "Shodan",
        "supports": ["ports", "IP"],
        "description": "Checks Shodan, reversed obtained IP for a given domain/URL",
    },
    {
        "name": "phishtank",
        "label": "Phishtank",
        "supports": ["risk", "domain", "URL"],
        "description": "Checks Phishtank for domains, URL",
    },
    {
        "name": "threatfox",
        "label": "ThreatFox",
        "supports": ["IP", "domain", "URL"],
        "description": "Checks ThreatFox by Abuse.ch for IP, domains, URL",
    },
    {
        "name": "urlscan",
        "label": "URLscan",
        "supports": ["domain", "URL", "IP", "hash"],
        "description": "Checks URLscan for all types of observable",
    },
    {
        "name": "google",
        "label": "Google",
        "supports": ["domain", "URL", "IP", "hash", "chrome_extension_id", "edge_extension_id"],
        "description": "Scraps Google search results for all types of observable",
    },
    {
        "name": "github",
        "label": "Github",
        "supports": ["domain", "URL", "IP", "hash", "chrome_extension_id", "edge_extension_id"],
        "description": "Get Github grep.app API search results for all types of observable",
    },
    {
        "name": "ioc_one_html",
        "label": "Ioc.One (HTML)",
        "supports": ["domain", "URL", "IP", "hash", "chrome_extension_id", "edge_extension_id"],
        "description": "Scraps (can be long) Ioc.One HTML search results for all types of observable",
    },
    {
        "name": "ioc_one_pdf",
        "label": "Ioc.One (PDF)",
        "supports": ["domain", "URL", "IP", "hash", "chrome_extension_id", "edge_extension_id"],
        "description": "Scraps (can be long) Ioc.One PDF search results for all types of observable",
    },
    {
        "name": "opencti",
        "label": "OpenCTI",
        "supports": ["domain", "URL", "IP", "hash"],
        "description": "Searches OpenCTI results for all types of observable",
    },
    {
        "name": "abusix",
        "label": "Abusix",
        "supports": ["abuse", "IP"],
        "description": "Checks abuse contact with Abusix for IP, reversed obtained IP for a given domain/URL",
    },
    {
        "name": "hudsonrock",
        "label": "Hudson Rock",
        "supports": ["domain", "URL", "email", "infostealers", "malware"],
        "description": "Searches Hudson Rocks results for domains, URL, Email",
    },
    {
        "name": "webscout",
        "label": "WebScout",
        "supports": ["IP", "risk", "geoloc", "VPN", "proxy"],
        "description": "Checks WebScout for IP, reversed obtained IP for a given domain / URL",
    },
    {
        "name": "criminalip",
        "label": "CriminalIP",
        "supports": ["IP", "risk", "VPN", "proxy"],
        "description": "Checks CriminalIP for IP, reversed obtained IP for a given domain / URL",
    },
    {
        "name": "alienvault",
        "label": "Alienvault",
        "supports": ["IP", "domain", "URL", "hash", "risk"],
        "description": "Checks Alienvault for IP, domain, URL, hash",
    },
    {
        "name": "misp",
        "label": "MISP",
        "supports": ["IP", "domain", "URL", "hash"],
        "description": "Checks MISP for IP, domain, URL, hash",
    },
    {
        "name": "google_dns",
        "label": "Google DNS (common records)",
        "supports": ["IP", "domain", "URL"],
        "description": "Checks Google common DNS records (A, AAAA, CNAME, NS, MX, TXT, PTR) for IP, domain, URL",
    },
]

mcp = FastMCP("CyberbroMCP")

# --- MCP tool functions for the existing tools in list_tools ---


@mcp.tool()
async def analyze_observable(text: str, engines: list[str]) -> Any:
    """
    Trigger an analysis for a given observable (IP, domain, URL, hash, chrome extension id) using Cyberbro.
    It can support multiple observables at once separated by spaces.
    Args:
        text: Observable(s) to analyze.
        engines: List of engine names.
    Returns:
        The analysis response from Cyberbro API.
    """
    try:
        async with httpx.AsyncClient() as client:
            payload = {"text": text, "engines": engines}
            response = await client.post(f"{CYBERBRO_API}/analyze", json=payload)
            response.raise_for_status()
            return response.json()
    except Exception as e:
        return {"error": f"Error executing tool analyze_observable: {str(e)}"}


@mcp.tool()
async def is_analysis_complete(analysis_id: str) -> Any:
    """
    Check if the analysis is complete for the given analysis_id.
    Args:
        analysis_id: Analysis ID to check.
    Returns:
        The completion status from Cyberbro API.
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{CYBERBRO_API}/is_analysis_complete/{analysis_id}")
            response.raise_for_status()
            return response.json()
    except Exception as e:
        return {"error": f"Error executing tool is_analysis_complete: {str(e)}"}


@mcp.tool()
async def get_analysis_results(analysis_id: str) -> Any:
    """
    Retrieve the results of a previous analysis by analysis_id.
    Args:
        analysis_id: Analysis ID to retrieve results for.
    Returns:
        The analysis results from Cyberbro API.
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{CYBERBRO_API}/results/{analysis_id}")
            response.raise_for_status()
            return response.json()
    except Exception as e:
        return {"error": f"Error executing tool get_analysis_results: {str(e)}"}


@mcp.tool()
async def get_engines() -> Any:
    """
    List available Cyberbro engines.
    Returns:
        The list of engines.
    """
    try:
        return {"engines": ENGINES}
    except Exception as e:
        return {"error": f"Error executing tool get_engines: {str(e)}"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cyberbro MCP Server")
    parser.add_argument(
        "--cyberbro_url", type=str, required=False, help="Base URL for Cyberbro API (env: CYBERBRO_URL)"
    )
    parser.add_argument("--api_prefix", type=str, default=None, help="API prefix path (env: API_PREFIX, default: api)")
    args = parser.parse_args()

    CYBERBRO_URL = args.cyberbro_url or os.environ.get("CYBERBRO_URL")
    API_PREFIX = args.api_prefix or os.environ.get("API_PREFIX", "api")

    if not CYBERBRO_URL:
        raise ValueError("cyberbro_url must be provided as --cyberbro_url or CYBERBRO_URL env variable")

    CYBERBRO_API = CYBERBRO_URL.rstrip("/") + "/" + API_PREFIX.strip("/")
    mcp.run(transport="stdio")
