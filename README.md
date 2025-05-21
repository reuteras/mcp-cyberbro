<h1 align="center">Cyberbro MCP Server</h1>

<p align="center">
<img src="https://github.com/user-attachments/assets/5e5a4406-99c1-47f1-a726-de176baa824c" width="90" /><br />
<b><i>A simple application that extracts your IoCs from garbage input and checks their reputation using multiple services.</i></b>
<br />
<b>🌐 <a href="https://demo.cyberbro.net/">demo.cyberbro.net</a></b><br />

</p>

![mcp-cyberbro-demo](https://github.com/user-attachments/assets/99ee5538-c95a-40ca-bff5-3cdf3aa86235)

A Model Context Protocol (MCP) server for Cyberbro that provides a comprehensive interface for extracting and analyzing Indicators of Compromise (IoCs) from unstructured input, and checking their reputation using multiple threat intelligence services.

Checkout [Cyberbro](https://github.com/stanfrbd/cyberbro) repository for more information about the platform.

## Overview

This MCP server enables interaction with the Cyberbro platform through the Model Context Protocol. MCP is a standard that allows applications to provide context and functionality to Large Language Models (LLMs) in a secure, standardized way—similar to a web API, but designed for LLM integrations.

MCP servers can:
- Expose data through **Resources** (to load information into the LLM's context)
- Provide functionality through **Tools** (to execute code or perform actions)
- Define interaction patterns through **Prompts** (reusable templates for LLM interactions)

This server implements the Tools functionality of MCP, offering a suite of tools for extracting IoCs from text, analyzing them, and checking their reputation across various threat intelligence sources. It allows AI systems like Claude to retrieve, analyze, and act on threat intelligence in real-time.

## Features

- **Multi-Service Reputation Checks**: Query IPs, domains, hashes, URLs, and Chrome extension IDs across many threat intelligence sources.
- **Integrated Reporting**: Get detailed, exportable reports and analysis history.
- **Platform Integrations**: Supports Microsoft Defender for Endpoint, CrowdStrike, OpenCTI, and more.
- **Advanced Search & Visualization**: Search with Grep.App, check for breaches, and visualize results.

## Why Use Cyberbro with LLMs

- **LLM-Ready**: Designed for seamless use via MCP with Claude or other LLMs—no manual UI needed.
- **Beginner-Friendly**: Simple, accessible, and easy to deploy.
- **Unique Capabilities**: Chrome extension ID lookups, advanced TLD handling, and pragmatic intelligence gathering.
- **Comprehensive CTI Access**: Leverages multiple sources and integrates CTI reports for enriched context.


## Installation

### Option 1: Using Docker (Recommended)

1. Export your Cyberbro config as an environment variable:
   ```
    export CYBERBRO_URL=http://localhost:5000
    # The API prefix is optional, but if you have a custom prefix, set it here.
    export API_PREFIX=api
   ```

3. Pull the Docker image from GitHub Container Registry:
   ```
   docker pull ghcr.io/stanfrbd/mcp-cyberbro:latest
   ```

### Option 2: Local Installation

1. Clone this repository:
    ```
    git clone https://github.com/stanfrbd/mcp-cyberbro.git
    cd mcp-cyberbro
    ```
2. Install the required dependencies:
    ```
    uv run pip install -r requirements.txt
    ```
3. Set environment variables for MCP configuration **or** provide them as CLI arguments:

    **Option A: Using environment variables**
    ```
    export CYBERBRO_URL=http://localhost:5000
    export API_PREFIX=api
    ```

    **Option B: Using CLI arguments**
    ```
    uv run mcp-cyberbro-server.py --cyberbro_url http://localhost:5000 --api_prefix api
    ```
4. Start the MCP server:
    ```
    uv run mcp-cyberbro-server.py
    ```
    The server will listen for MCP protocol messages on stdin/stdout and use the environment variables as shown in the Claude Desktop configuration example.

## Usage

### Using with Claude Desktop (Docker) - Recommended

> [!NOTE]
> In this configuration, make sure Docker is installed and running on your machine (e.g., Docker Desktop).

To use this MCP server with Claude Desktop, add the following to your Claude Desktop config file (`claude_desktop_config.json`):

```json
"mcpServers": {
  "cyberbro": {
    "command": "docker",
    "args": [
      "run",
      "-i",
      "--rm",
      "-e",
      "CYBERBRO_URL",
      "-e",
      "API_PREFIX",
      "ghcr.io/stanfrbd/mcp-cyberbro:latest"
    ],
    "env": {
      "CYBERBRO_URL": "http://localhost:5000",
      "API_PREFIX": "api"
    }
  }
}
```

## Using with Claude Desktop (Local)

> [!WARNING]
> In this configuration, make sure to use `venv` or `uv` to avoid conflicts with other Python packages.

To use this MCP server with Claude Desktop locally, add the following to your Claude Desktop config file (`claude_desktop_config.json`):

```json
"mcpServers": {
  "cyberbro": {
    "command": "uv",
    "args": [
      "run",
      "C:\\Users\\path\\to\\mcp-cyberbro-server.py"
    ],
    "env": {
      "CYBERBRO_URL": "http://localhost:5000",
      "API_PREFIX": "api"
    }
  }
}
```

> [!IMPORTANT]
> **Make sure you have exported your Cyberbro config as environment variables** (e.g., `CYBERBRO_URL` and `API_PREFIX`) **before starting Claude Desktop**. This ensures the MCP server can connect to your Cyberbro instance correctly.

## Using with other LLMs and MCP Clients
This MCP server can be used with any LLM or MCP client that supports the Model Context Protocol. The server listens for MCP protocol messages on stdin/stdout, making it compatible with various LLMs and clients. BUT, it is important to note that the server is designed to work with LLMs that can interpret and execute the MCP commands correctly. I tried it personlly with OpenAI (in Open Web UI) and it is not as good as Claude Desktop.

Documentation for other LLMs and MCP clients with Open Web UI: https://docs.openwebui.com/openapi-servers/mcp/

It uses a OpenAPI proxy to expose the MCP server as an OpenAPI server, allowing you to interact with it using standard HTTP requests. This makes it easy to integrate with other applications and services that support OpenAPI.

## Example of usage with OpenAPI Proxy

```
uvx mcpo --port 8000 -- uv run mcp-cyberbro-server.py --cyberbro_url "http://cyberbro.lab.local"
```

```bash
uvx mcpo --port 8000 -- uv run mcp-cyberbro-server.py --cyberbro_url "http://cyberbro.lab.local"
Starting MCP OpenAPI Proxy on 0.0.0.0:8000 with command: uv run mcp-cyberbro-server.py --cyberbro_url http://cyberbro.lab.local
2025-05-21 11:02:57,819 - INFO - Starting MCPO Server...
2025-05-21 11:02:57,819 - INFO -   Name: MCP OpenAPI Proxy
2025-05-21 11:02:57,819 - INFO -   Version: 1.0
2025-05-21 11:02:57,819 - INFO -   Description: Automatically generated API from MCP Tool Schemas
2025-05-21 11:02:57,819 - INFO -   Hostname: docker-services
2025-05-21 11:02:57,819 - INFO -   Port: 8000
2025-05-21 11:02:57,819 - INFO -   API Key: Not Provided
2025-05-21 11:02:57,819 - INFO -   CORS Allowed Origins: ['*']
2025-05-21 11:02:57,819 - INFO -   Path Prefix: /
2025-05-21 11:02:57,819 - INFO - Configuring for a single Stdio MCP Server with command: uv run mcp-cyberbro-server.py --cyberbro_url http://cyberbro.lab.local
2025-05-21 11:02:57,820 - INFO - Uvicorn server starting...
INFO:     Started server process [3920625]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

**You must then choose the correct configuration for your LLM / desktop app.**

### Using with Other MCP Clients

This MCP server is designed to be used with any MCP-compatible client. The server listens for MCP protocol messages on stdin/stdout, making it compatible with various MCP clients that can execute Docker containers.

## Available Tools

The MCP server provides the following tools:

### Tool List

| Tool Name              | Description                                                                                  | Arguments                                      |
|------------------------|----------------------------------------------------------------------------------------------|------------------------------------------------|
| **analyze_observable** | Extracts and analyzes IoCs from input text using selected engines. Returns analysis ID.      | `text` (string), `engines` (list, optional)    |
| **is_analysis_complete** | Checks if the analysis for a given ID is finished. Returns status.                         | `analysis_id` (string)                         |
| **get_analysis_results** | Retrieves the results of a completed analysis by ID.                                       | `analysis_id` (string)                         |
| **get_engines**        | Lists available analysis engines supported by Cyberbro.                                      | *(none)*                                       |

#### Tool Details

- **analyze_observable**
  - **Purpose:** Extracts indicators from unstructured text and submits them for analysis.
  - **Arguments:**
    - `text` (required): The input text containing IoCs.
    - `engines` (optional): List of engines to use for analysis.
  - **Returns:** JSON with analysis ID and submission details.

- **is_analysis_complete**
  - **Purpose:** Checks if the analysis for a given `analysis_id` is complete.
  - **Arguments:**
    - `analysis_id` (required): The ID returned by `analyze_observable`.
  - **Returns:** JSON with completion status.

- **get_analysis_results**
  - **Purpose:** Retrieves the results of a completed analysis.
  - **Arguments:**
    - `analysis_id` (required): The ID of the analysis.
  - **Returns:** JSON with analysis results.

- **get_engines**
  - **Purpose:** Lists all available analysis engines.
  - **Arguments:** None.
  - **Returns:** JSON with available engines.

## Example Queries

Here are some example queries you can run using the MCP server with an LLM like Claude:

### Getting Indicator Details

```
Cyberbro: Check indicators for target.com
```

```
Can you check this IP reputation with Cyberbro? 192.168.1.1
Use github, google and virustotal engines.
```

```
I want to analyze the domain example.com. What can Cyberbro tell me about it?
Use max 3 engines.
```

```
Analyze these observables with Cyberbro: suspicious-domain.com, 8.8.8.8, and 44d88612fea8a8f36de82e1278abb02f. Use all available engines.
```

### Observable Analysis

```
I found this (hash|domain|url|ip|extension) Can you submit it for analysis to Cyberbro and analyze the results?
```

These example queries show how Cyberbro leverages LLMs to interpret your intent and automatically select the right MCP tools, allowing you to interact with Cyberbro easily—without needing to make the analysis yourself.

### OSINT investigation

```
Create an OSINT report for the domain example.com using Cyberbro.
Use all available engines. and pivot on the results for more information.
Use a maximum of 10 analysis requests.
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Model Context Protocol](https://modelcontextprotocol.io)
- [Cyberbro](https://github.com/stanfrbd/cyberbro)
