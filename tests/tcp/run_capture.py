#!/usr/bin/env python3
"""Own a real oracle for a bounded latest-UF/HF TCP capture, then clean it up."""
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tests/interop'))
import runtime
from start_oracle import create_oracle
from senders import sender_ready


def main():
    existing=subprocess.run(['docker','inspect','hec-spec-oracle'],capture_output=True,timeout=30)
    if existing.returncode==0:raise RuntimeError('refusing to adopt an existing oracle')
    owned=create_oracle()
    try:
        sender_ready('hec-spec-oracle')
        subprocess.run([sys.executable,str(ROOT/'tests/tcp/capture.py'),'--receiver','127.0.0.1:19997',*sys.argv[1:]],check=True,timeout=1500)
    finally:subprocess.run(['docker','rm','-f','-v',owned],capture_output=True,timeout=60)


if __name__=='__main__':main()
