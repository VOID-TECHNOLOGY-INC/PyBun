"""
B6: Lazy Import Benchmark

Measures lazy import effectiveness.

Scenarios:
- B6.1: Heavy module import (numpy/pandas)
- B6.2: Many small module imports
- B6.3: Actual access timing
"""

from __future__ import annotations

import tempfile
from pathlib import Path

# These are injected by bench.py when loading this module
# scenario, BenchResult, find_tool, measure_command


# Script to test standard imports
STANDARD_IMPORT_SCRIPT = '''\
#!/usr/bin/env python3
"""Standard import timing."""
import sys
import time

start = time.perf_counter_ns()
{imports}
end = time.perf_counter_ns()

print(f"{{(end - start) / 1e6:.2f}}")
'''

# Script to test lazy imports with pybun
LAZY_IMPORT_SCRIPT = '''\
#!/usr/bin/env python3
"""Lazy import timing - measures time until first actual use."""
import sys
import time

# Import time (lazy, should be fast)
start_import = time.perf_counter_ns()
{imports}
end_import = time.perf_counter_ns()

# Access time (triggers actual load)
start_access = time.perf_counter_ns()
{accesses}
end_access = time.perf_counter_ns()

import_ms = (end_import - start_import) / 1e6
access_ms = (end_access - start_access) / 1e6
total_ms = import_ms + access_ms

print(f"import:{{import_ms:.2f}},access:{{access_ms:.2f}},total:{{total_ms:.2f}}")
'''

# Script with many small imports
MANY_IMPORTS_SCRIPT = '''\
#!/usr/bin/env python3
"""Many small imports timing."""
import time

start = time.perf_counter_ns()
import os
import sys
import json
import re
import pathlib
import collections
import functools
import itertools
import datetime
import logging
import typing
import dataclasses
import urllib.parse
import http.client
import email.mime.text
import xml.etree.ElementTree
import sqlite3
import csv
import hashlib
import base64
import struct
import io
import copy
import operator
import math
import random
import string
import textwrap
import shutil
import tempfile
import subprocess
import threading
import queue
import socket
import select
import signal
end = time.perf_counter_ns()

print(f"{(end - start) / 1e6:.2f}")
'''


def lazy_import_benchmark(config: dict, scenario_config: dict, base_dir: Path) -> list:
    """Run lazy import benchmarks."""
    results: list[BenchResult] = []
    
    general = config.get("general", {})
    iterations = general.get("iterations", 5)
    warmup = general.get("warmup", 1)
    trim_ratio = scenario_config.get("trim_ratio", general.get("trim_ratio", 0.0))
    dry_run = config.get("dry_run", False)
    verbose = config.get("verbose", False)
    
    # Find tools
    pybun_path = find_tool("pybun", config)
    python_path = find_tool("python3", config) or find_tool("python", config)
    
    heavy_modules = scenario_config.get("heavy_modules", ["numpy", "pandas", "matplotlib"])
    
    with tempfile.TemporaryDirectory(prefix="pybun_lazy_bench_") as tmpdir:
        tmp = Path(tmpdir)
        
        # === B6.1: Heavy Module Import ===
        print("\n--- B6.1: Heavy Module Import ---")
        
        for module in heavy_modules:
            print(f"\n  Testing: {module}")
            
            # Standard Python import
            script = tmp / f"standard_{module}.py"
            script.write_text(STANDARD_IMPORT_SCRIPT.format(imports=f"import {module}"))
            
            if python_path:
                cmd = [python_path, str(script)]
                if dry_run:
                    print(f"    Would run: {' '.join(cmd)}")
                else:
                    if verbose:
                        print(f"    Running: {' '.join(cmd)}")
                    result = measure_command(
                        cmd,
                        warmup=warmup,
                        iterations=iterations,
                        trim_ratio=trim_ratio,
                    )
                    result.scenario = f"B6.1_heavy_{module}"
                    result.tool = "python"
                    result.metadata["module"] = module
                    result.metadata["mode"] = "standard"
                    results.append(result)
                    print(f"    python (standard): {result.duration_ms:.2f}ms")
            
            # PyBun with lazy import
            if pybun_path:
                # Generate lazy import code
                lazy_script = tmp / f"lazy_{module}.py"
                lazy_script.write_text(f'''\
#!/usr/bin/env python3
import time
start = time.perf_counter_ns()
import {module}
end = time.perf_counter_ns()
print(f"{{(end - start) / 1e6:.2f}}")
''')
                
                # Run with lazy import enabled
                cmd = [pybun_path, "run", str(lazy_script)]
                if dry_run:
                    print(f"    Would run: {' '.join(cmd)}")
                else:
                    if verbose:
                        print(f"    Running: {' '.join(cmd)}")
                    result = measure_command(
                        cmd,
                        warmup=warmup,
                        iterations=iterations,
                        env={"PYBUN_LAZY_IMPORT": "1"},
                        trim_ratio=trim_ratio,
                    )
                    result.scenario = f"B6.1_heavy_{module}"
                    result.tool = "pybun_lazy"
                    result.metadata["module"] = module
                    result.metadata["mode"] = "lazy"
                    results.append(result)
                    print(f"    pybun (lazy): {result.duration_ms:.2f}ms")
        
        # === B6.2: Many Small Module Imports ===
        print("\n--- B6.2: Many Small Module Imports ---")
        
        script = tmp / "many_imports.py"
        script.write_text(MANY_IMPORTS_SCRIPT)
        
        if python_path:
            cmd = [python_path, str(script)]
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
                result.scenario = "B6.2_many_imports"
                result.tool = "python"
                result.metadata["import_count"] = 40
                results.append(result)
                print(f"  python (40 imports): {result.duration_ms:.2f}ms")
        
        if pybun_path:
            cmd = [pybun_path, "run", str(script)]
            if dry_run:
                print(f"  Would run: {' '.join(cmd)}")
            else:
                if verbose:
                    print(f"  Running: {' '.join(cmd)}")
                result = measure_command(
                    cmd,
                    warmup=warmup,
                    iterations=iterations,
                    env={"PYBUN_LAZY_IMPORT": "1"},
                    trim_ratio=trim_ratio,
                )
                result.scenario = "B6.2_many_imports"
                result.tool = "pybun_lazy"
                result.metadata["import_count"] = 40
                results.append(result)
                print(f"  pybun lazy (40 imports): {result.duration_ms:.2f}ms")
        
        # === B6.3: Actual Access Timing ===
        print("\n--- B6.3: Actual Access Timing ---")
        
        access_script = tmp / "access_timing.py"
        access_script.write_text('''\
#!/usr/bin/env python3
"""Measures time to import vs time to first use."""
import time

# Time the import
start_import = time.perf_counter_ns()
import json
import os
import sys
import re
import pathlib
end_import = time.perf_counter_ns()

# Time the first access
start_access = time.perf_counter_ns()
_ = json.dumps({"test": 1})
_ = os.getcwd()
_ = sys.version
_ = re.match(r"test", "test")
_ = pathlib.Path(".")
end_access = time.perf_counter_ns()

import_ms = (end_import - start_import) / 1e6
access_ms = (end_access - start_access) / 1e6
print(f"import:{import_ms:.2f},access:{access_ms:.2f}")
''')
        
        if python_path:
            cmd = [python_path, str(access_script)]
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
                result.scenario = "B6.3_access_timing"
                result.tool = "python"
                results.append(result)
                print(f"  python: {result.duration_ms:.2f}ms")
        
        if pybun_path:
            cmd = [pybun_path, "run", str(access_script)]
            if dry_run:
                print(f"  Would run: {' '.join(cmd)}")
            else:
                if verbose:
                    print(f"  Running: {' '.join(cmd)}")
                result = measure_command(
                    cmd,
                    warmup=warmup,
                    iterations=iterations,
                    env={"PYBUN_LAZY_IMPORT": "1"},
                    trim_ratio=trim_ratio,
                )
                result.scenario = "B6.3_access_timing"
                result.tool = "pybun_lazy"
                results.append(result)
                print(f"  pybun lazy: {result.duration_ms:.2f}ms")
    
    return results
