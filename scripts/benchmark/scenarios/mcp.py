"""
B8: MCP/JSON Output Benchmark

Measures MCP server response latency.

Scenarios:
- B8.1: pybun_doctor response time
- B8.2: pybun_run response time
- B8.3: pybun_resolve response time
- B8.4: JSON output overhead
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import time
from pathlib import Path

# These are injected by bench.py when loading this module
# scenario, BenchResult, find_tool, measure_command


def send_mcp_request(pybun_path: str, request: dict, timeout: int = 30) -> tuple[dict | None, float]:
    """
    Send a JSON-RPC request to MCP server and measure response time.
    Returns (response, elapsed_ms).
    """
    request_json = json.dumps(request)
    
    start = time.perf_counter()
    try:
        proc = subprocess.Popen(
            [pybun_path, "mcp", "serve", "--stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        
        # Send request
        stdout, stderr = proc.communicate(input=request_json + "\n", timeout=timeout)
        
        end = time.perf_counter()
        elapsed_ms = (end - start) * 1000
        
        # Parse response
        if stdout:
            try:
                response = json.loads(stdout.strip().split("\n")[-1])
                return response, elapsed_ms
            except json.JSONDecodeError:
                return None, elapsed_ms
        
        return None, elapsed_ms
        
    except subprocess.TimeoutExpired:
        proc.kill()
        return None, timeout * 1000
    except Exception as e:
        return None, 0.0


def measure_mcp_tool(
    pybun_path: str,
    tool_name: str,
    arguments: dict,
    iterations: int = 5,
    warmup: int = 1,
) -> BenchResult:
    """Measure MCP tool call latency."""
    # Initialize request
    init_request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "benchmark", "version": "1.0.0"},
        },
    }
    
    # Tool call request
    call_request = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments,
        },
    }
    
    times: list[float] = []
    success = True
    last_error = None
    
    # Warmup
    for _ in range(warmup):
        send_mcp_request(pybun_path, init_request)
        send_mcp_request(pybun_path, call_request)
    
    # Timed runs
    for _ in range(iterations):
        _, init_time = send_mcp_request(pybun_path, init_request)
        response, call_time = send_mcp_request(pybun_path, call_request)
        
        if response is None:
            success = False
            last_error = "No response from MCP server"
        elif "error" in response:
            success = False
            last_error = response.get("error", {}).get("message", "Unknown error")
        
        times.append(init_time + call_time)
    
    import statistics
    avg = statistics.mean(times) if times else 0
    min_t = min(times) if times else 0
    max_t = max(times) if times else 0
    stddev = statistics.stdev(times) if len(times) > 1 else 0
    
    return BenchResult(
        scenario="",
        tool="pybun_mcp",
        duration_ms=round(avg, 2),
        min_ms=round(min_t, 2),
        max_ms=round(max_t, 2),
        stddev_ms=round(stddev, 2),
        iterations=iterations,
        success=success,
        error=last_error if not success else None,
        metadata={"mcp_tool": tool_name},
    )


def mcp_benchmark(config: dict, scenario_config: dict, base_dir: Path) -> list:
    """Run MCP/JSON output benchmarks."""
    results: list[BenchResult] = []
    
    general = config.get("general", {})
    iterations = general.get("iterations", 5)
    warmup = general.get("warmup", 1)
    dry_run = config.get("dry_run", False)
    verbose = config.get("verbose", False)
    
    pybun_path = find_tool("pybun", config)
    if not pybun_path:
        print("  pybun not found, skipping MCP benchmarks")
        return results
    
    tools = scenario_config.get("tools", ["doctor", "run", "resolve", "gc"])
    
    with tempfile.TemporaryDirectory(prefix="pybun_mcp_bench_") as tmpdir:
        tmp = Path(tmpdir)
        
        # Create a simple script for run tests
        test_script = tmp / "test.py"
        test_script.write_text('print("Hello from MCP!")')
        
        # === B8.1: pybun_doctor Response Time ===
        if "doctor" in tools:
            print("\n--- B8.1: pybun_doctor Response Time ---")
            
            if dry_run:
                print(f"  Would call MCP tool: pybun_doctor")
            else:
                if verbose:
                    print(f"  Calling MCP tool: pybun_doctor")
                result = measure_mcp_tool(
                    pybun_path,
                    "pybun_doctor",
                    {},
                    iterations=iterations,
                    warmup=warmup,
                )
                result.scenario = "B8.1_doctor"
                results.append(result)
                print(f"  pybun_doctor: {result.duration_ms:.2f}ms")
        
        # === B8.2: pybun_run Response Time ===
        if "run" in tools:
            print("\n--- B8.2: pybun_run Response Time ---")
            
            if dry_run:
                print(f"  Would call MCP tool: pybun_run")
            else:
                if verbose:
                    print(f"  Calling MCP tool: pybun_run")
                
                # Test with inline code
                result = measure_mcp_tool(
                    pybun_path,
                    "pybun_run",
                    {"code": "print('Hello')"},
                    iterations=iterations,
                    warmup=warmup,
                )
                result.scenario = "B8.2_run_inline"
                result.metadata["mode"] = "inline"
                results.append(result)
                print(f"  pybun_run (inline): {result.duration_ms:.2f}ms")
                
                # Test with script file
                result = measure_mcp_tool(
                    pybun_path,
                    "pybun_run",
                    {"script": str(test_script)},
                    iterations=iterations,
                    warmup=warmup,
                )
                result.scenario = "B8.2_run_script"
                result.metadata["mode"] = "script"
                results.append(result)
                print(f"  pybun_run (script): {result.duration_ms:.2f}ms")
        
        # === B8.3: pybun_resolve Response Time ===
        if "resolve" in tools:
            print("\n--- B8.3: pybun_resolve Response Time ---")
            
            if dry_run:
                print(f"  Would call MCP tool: pybun_resolve")
            else:
                if verbose:
                    print(f"  Calling MCP tool: pybun_resolve")
                result = measure_mcp_tool(
                    pybun_path,
                    "pybun_resolve",
                    {"requirements": ["requests>=2.28.0"]},
                    iterations=iterations,
                    warmup=warmup,
                )
                result.scenario = "B8.3_resolve"
                results.append(result)
                print(f"  pybun_resolve: {result.duration_ms:.2f}ms")
        
        # === B8.4: JSON Output Overhead ===
        print("\n--- B8.4: JSON Output Overhead ---")
        
        # Compare text vs JSON output for same command
        simple_script = tmp / "simple.py"
        simple_script.write_text('print("test")')
        
        # Text output
        cmd = [pybun_path, "run", str(simple_script)]
        if dry_run:
            print(f"  Would run: {' '.join(cmd)}")
        else:
            if verbose:
                print(f"  Running: {' '.join(cmd)}")
            result = measure_command(
                cmd,
                warmup=warmup,
                iterations=iterations,
            )
            result.scenario = "B8.4_json_overhead"
            result.tool = "pybun_text"
            result.metadata["format"] = "text"
            results.append(result)
            text_time = result.duration_ms
            print(f"  pybun run (text): {result.duration_ms:.2f}ms")
        
        # JSON output
        cmd = [pybun_path, "run", str(simple_script), "--format=json"]
        if dry_run:
            print(f"  Would run: {' '.join(cmd)}")
        else:
            if verbose:
                print(f"  Running: {' '.join(cmd)}")
            result = measure_command(
                cmd,
                warmup=warmup,
                iterations=iterations,
            )
            result.scenario = "B8.4_json_overhead"
            result.tool = "pybun_json"
            result.metadata["format"] = "json"
            results.append(result)
            json_time = result.duration_ms
            print(f"  pybun run (json): {result.duration_ms:.2f}ms")
            
            if text_time > 0:
                overhead = ((json_time - text_time) / text_time) * 100
                print(f"  JSON overhead: {overhead:.1f}%")
    
    return results

