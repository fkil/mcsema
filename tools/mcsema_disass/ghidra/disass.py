#!/usr/bin/env python
# Copyright (c) 2017 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import collections
import itertools
import os
import subprocess
import sys
import traceback

try:
  from shlex import quote
except:
  from pipes import quote

def execute(args, command_args):
  """Execute Ghidra as a subprocess, passing this file in as a batch-mode
  script for Ghidrato run. This forwards along arguments passed to `mcsema-disass`
  down into the Ghidra script. `command_args` contains unparsed arguments passed
  to `mcsema-disass`. This script may handle extra arguments."""

  ghidra_disass_path = os.path.abspath(__file__)
  ghidra_dir = os.path.dirname(ghidra_disass_path)
  ghidra_get_cfg_path = os.path.join(ghidra_dir, "get_cfg.py")

  env = {}
  env["HOME"] = os.path.expanduser('~')
  env["PYTHONPATH"] = os.path.dirname(ghidra_dir)
  env["PATH"] = os.environ["PATH"]
  if "SystemRoot" in os.environ:
    env["SystemRoot"] = os.environ["SystemRoot"]

  script_cmd = []
  script_cmd.append(" ")
  script_cmd.append("--output")
  script_cmd.append(args.output)
  script_cmd.append("--log_file")
  script_cmd.append(args.log_file)
  script_cmd.append("--arch")
  script_cmd.append(args.arch)
  script_cmd.append("--os")
  script_cmd.append(args.os)
  if args.rebase:
    script_cmd.append("--rebase")
    script_cmd.append(str(args.rebase))
  if args.entrypoint is not None and len(args.entrypoint):
    script_cmd.append("--entrypoint")
    script_cmd.append(args.entrypoint)
  script_cmd.extend(command_args)  # Extra, script-specific arguments.

  cmd = []
  cmd.append(args.disassembler)  # Path to ghidra headless analyzer.
  cmd.append(os.path.dirname(args.binary))
  cmd.append(os.path.basename(args.binary))
  cmd.append("-import")  # Batch mode.
  cmd.append(args.binary)  # Batch mode.
  cmd.append("-postscript")
  cmd.append(ghidra_get_cfg_path)
  cmd.append(" ".join(script_cmd))

  try:
    with open(os.devnull, "w") as devnull:
      return subprocess.check_call(
          cmd,
          env=env, 
          stdin=None, 
          stdout=sys.stdout,  # Necessary.
          stderr=sys.stderr,  # For enabling `--log_file /dev/stderr`.
          cwd=os.path.dirname(__file__))

  except:
    sys.stderr.write(traceback.format_exc())
    return 1
