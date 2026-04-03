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

import io
import json
import select
import subprocess
import tempfile
import time
from pathlib import Path

# These are injected by bench.py when loading this module
# scenario, BenchResult, find_tool, measure_command


def _response_key(request_id: object) -> str:
    return json.dumps(request_id, sort_keys=True)


def _extract_tool_text(result: dict) -> str | None:
    content = result.get("content")
    if not isinstance(content, list):
        return None
    for item in content:
        if isinstance(item, dict) and isinstance(item.get("text"), str):
            return item["text"]
    return None


def tool_response_error(response: dict | None) -> str | None:
    """Return an error string when the MCP response represents a failed tool call."""
    if response is None:
        return "No response from MCP server"

    if isinstance(response.get("error"), dict):
        return response["error"].get("message", "Unknown JSON-RPC error")

    result = response.get("result")
    if not isinstance(result, dict):
        return None

    text = _extract_tool_text(result)
    if result.get("isError"):
        return text or "MCP tool call failed"

    if not text:
        return None

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None

    if not isinstance(payload, dict):
        return None

    if payload.get("status") == "error":
        return payload.get("stderr") or payload.get("message") or "Tool returned status=error"

    exit_code = payload.get("exit_code")
    if isinstance(exit_code, int) and exit_code != 0:
        return payload.get("stderr") or f"Tool exited with code {exit_code}"

    return None


class McpStdioSession:
    """Line-oriented stdio client for a single MCP server process."""

    def __init__(self, pybun_path: str) -> None:
        self._proc = subprocess.Popen(
            [pybun_path, "mcp", "serve", "--stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._pending: dict[str, dict] = {}

    def __enter__(self) -> "McpStdioSession":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        stdin_closed = getattr(self._proc.stdin, "closed", False)
        if self._proc.stdin and not stdin_closed:
            self._proc.stdin.close()
        try:
            self._proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=1)

    def send_request(self, request: dict, timeout: int = 30) -> tuple[dict | None, float]:
        """Send one request and wait for the matching response id."""
        expected_id = request.get("id")
        key = _response_key(expected_id)
        start = time.perf_counter()

        if self._proc.stdin is None:
            return None, 0.0

        self._proc.stdin.write(json.dumps(request) + "\n")
        self._proc.stdin.flush()

        if key in self._pending:
            response = self._pending.pop(key)
            return response, (time.perf_counter() - start) * 1000

        response = self._read_response(expected_id, timeout)
        elapsed_ms = (time.perf_counter() - start) * 1000
        return response, elapsed_ms

    def _read_response(self, expected_id: object, timeout: int) -> dict | None:
        expected_key = _response_key(expected_id)
        deadline = time.perf_counter() + timeout

        if expected_key in self._pending:
            return self._pending.pop(expected_key)

        while time.perf_counter() < deadline:
            remaining = deadline - time.perf_counter()
            line = self._readline_with_timeout(remaining)
            if line is None:
                continue

            stripped = line.strip()
            if not stripped:
                continue

            try:
                response = json.loads(stripped)
            except json.JSONDecodeError:
                continue

            if not isinstance(response, dict) or "id" not in response:
                continue

            response_key = _response_key(response.get("id"))
            if response_key == expected_key:
                return response
            self._pending[response_key] = response

        return None

    def _readline_with_timeout(self, timeout: float) -> str | None:
        if self._proc.stdout is None:
            return None

        fileno = getattr(self._proc.stdout, "fileno", None)
        if callable(fileno):
            try:
                ready, _, _ = select.select([self._proc.stdout], [], [], timeout)
            except (OSError, ValueError, io.UnsupportedOperation):
                ready = None
            if ready == []:
                return None

        line = self._proc.stdout.readline()
        if line == "":
            if self._proc.poll() is not None:
                return None
        return line


def send_mcp_request(pybun_path: str, request: dict, timeout: int = 30) -> tuple[dict | None, float]:
    """
    Send a single JSON-RPC request in a fresh MCP stdio session.
    Kept for compatibility with tests/helpers that only need one round-trip.
    """
    try:
        with McpStdioSession(pybun_path) as session:
            return session.send_request(request, timeout=timeout)
    except Exception:
        return None, 0.0


def measure_mcp_round(
    pybun_path: str,
    init_request: dict,
    call_request: dict,
    timeout: int = 30,
) -> tuple[dict | None, dict | None, float]:
    """
    Measure one MCP benchmark sample using a single stdio server session.
    Returns (initialize_response, tool_response, tool_call_elapsed_ms).
    """
    with McpStdioSession(pybun_path) as session:
        init_response, _ = session.send_request(init_request, timeout=timeout)
        call_response, call_time = session.send_request(call_request, timeout=timeout)
    return init_response, call_response, call_time


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
        try:
            measure_mcp_round(pybun_path, init_request, call_request)
        except Exception:
            pass

    # Timed runs
    for _ in range(iterations):
        try:
            init_response, response, total_time = measure_mcp_round(
                pybun_path,
                init_request,
                call_request,
            )
        except Exception as exc:
            init_response = None
            response = None
            total_time = 0.0
            success = False
            last_error = str(exc)
        else:
            init_error = tool_response_error(init_response)
            call_error = tool_response_error(response)
            if init_error is not None:
                success = False
                last_error = init_error
            elif call_error is not None:
                success = False
                last_error = call_error

        times.append(total_time)
    
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
    trim_ratio = scenario_config.get("trim_ratio", general.get("trim_ratio", 0.0))
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
                trim_ratio=trim_ratio,
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
                trim_ratio=trim_ratio,
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
