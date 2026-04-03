import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import bench
from scenarios import mcp as mcp_scenario


mcp_scenario.BenchResult = bench.BenchResult


class FakeStdout:
    def __init__(self) -> None:
        self._lines: list[str] = []

    def push(self, line: str) -> None:
        if not line.endswith("\n"):
            line = f"{line}\n"
        self._lines.append(line)

    def readline(self) -> str:
        if self._lines:
            return self._lines.pop(0)
        return ""


class FakeStdin:
    def __init__(self, process: "FakeProcess") -> None:
        self._process = process
        self._buffer = ""
        self.closed = False

    def write(self, data: str) -> int:
        self._buffer += data
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            if line.strip():
                self._process.handle_request(line)
        return len(data)

    def flush(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True
        self._process.closed = True


class FakeProcess:
    def __init__(self, response_builder) -> None:
        self.stdin = FakeStdin(self)
        self.stdout = FakeStdout()
        self.stderr = FakeStdout()
        self._response_builder = response_builder
        self.requests: list[dict] = []
        self.closed = False
        self.returncode: int | None = None

    def handle_request(self, line: str) -> None:
        request = json.loads(line)
        self.requests.append(request)
        for response_line in self._response_builder(request):
            self.stdout.push(response_line)

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        self.returncode = 0
        return 0

    def terminate(self) -> None:
        self.returncode = 0

    def kill(self) -> None:
        self.returncode = -9


class TestMcpScenario(unittest.TestCase):
    def test_session_ignores_noise_and_matches_response_ids(self) -> None:
        def build_response(request: dict) -> list[str]:
            if request["method"] == "initialize":
                return [
                    "PyBun MCP server starting (stdio mode)...",
                    json.dumps({"jsonrpc": "2.0", "id": 2, "result": {"content": []}}),
                    json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05"}}),
                ]
            return []

        fake_process = FakeProcess(build_response)

        with mock.patch.object(mcp_scenario.subprocess, "Popen", return_value=fake_process):
            with mcp_scenario.McpStdioSession("pybun") as session:
                init_response, _ = session.send_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
                call_response, _ = session.send_request({"jsonrpc": "2.0", "id": 2, "method": "tools/call"})

        self.assertEqual(init_response["id"], 1)
        self.assertEqual(call_response["id"], 2)
        self.assertEqual([req["method"] for req in fake_process.requests], ["initialize", "tools/call"])

    def test_measure_mcp_tool_uses_one_session_per_sample(self) -> None:
        launched_processes: list[FakeProcess] = []

        def fake_popen(*args, **kwargs):
            def build_response(request: dict) -> list[str]:
                if request["method"] == "initialize":
                    return [json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": {"protocolVersion": "2024-11-05"}})]
                return [
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": request["id"],
                            "result": {
                                "content": [
                                    {
                                        "type": "text",
                                        "text": json.dumps({"status": "success", "exit_code": 0}),
                                    }
                                ]
                            },
                        }
                    )
                ]

            process = FakeProcess(build_response)
            launched_processes.append(process)
            return process

        with mock.patch.object(mcp_scenario.subprocess, "Popen", side_effect=fake_popen):
            result = mcp_scenario.measure_mcp_tool(
                "pybun",
                "pybun_run",
                {"code": "print('hello')"},
                iterations=2,
                warmup=1,
            )

        self.assertTrue(result.success)
        self.assertEqual(len(launched_processes), 3)
        for process in launched_processes:
            self.assertEqual(
                [request["method"] for request in process.requests],
                ["initialize", "tools/call"],
            )

    def test_measure_mcp_round_reports_only_tool_call_latency(self) -> None:
        init_response = {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05"}}
        call_response = {"jsonrpc": "2.0", "id": 2, "result": {"content": []}}

        session = mock.MagicMock()
        session.send_request.side_effect = [
            (init_response, 12.5),
            (call_response, 34.0),
        ]

        session_factory = mock.MagicMock()
        session_factory.__enter__.return_value = session
        session_factory.__exit__.return_value = None

        with mock.patch.object(mcp_scenario, "McpStdioSession", return_value=session_factory):
            actual_init, actual_call, elapsed_ms = mcp_scenario.measure_mcp_round(
                "pybun",
                {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call"},
            )

        self.assertEqual(actual_init, init_response)
        self.assertEqual(actual_call, call_response)
        self.assertEqual(elapsed_ms, 34.0)

    def test_measure_mcp_tool_marks_real_tool_failures(self) -> None:
        def fake_popen(*args, **kwargs):
            def build_response(request: dict) -> list[str]:
                if request["method"] == "initialize":
                    return [json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": {"protocolVersion": "2024-11-05"}})]
                return [
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": request["id"],
                            "result": {
                                "content": [{"type": "text", "text": json.dumps({"status": "error", "stderr": "boom"})}]
                            },
                        }
                    )
                ]

            return FakeProcess(build_response)

        with mock.patch.object(mcp_scenario.subprocess, "Popen", side_effect=fake_popen):
            result = mcp_scenario.measure_mcp_tool(
                "pybun",
                "pybun_run",
                {"code": "print('hello')"},
                iterations=1,
                warmup=0,
            )

        self.assertFalse(result.success)
        self.assertIn("boom", result.error)


if __name__ == "__main__":
    unittest.main()
