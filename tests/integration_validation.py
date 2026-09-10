# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import argparse
import http.server
import json
import pathlib
import queue
import shutil
import signal
import subprocess
import tempfile
import threading
import time


class ResultServer(http.server.ThreadingHTTPServer):
    def __init__(self, address, handler, page):
        super().__init__(address, handler)
        self.page = page
        self.result = queue.Queue(maxsize=1)
        self.reload = threading.Event()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/reload":
            self.send_response(200 if self.server.reload.is_set() else 204)
            self.end_headers()
            return
        if self.path == "/empty":
            self.send_response(204)
            self.end_headers()
            return
        if not self.path.startswith("/"):
            self.send_error(404)
            return
        body = self.server.page
        self.send_response(200)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/result":
            self.send_error(404)
            return
        length = int(self.headers.get("content-length", "0"))
        value = json.loads(self.rfile.read(length))
        if self.server.result.empty():
            self.server.result.put(value)
        self.send_response(204)
        self.end_headers()

    def log_message(self, format, *args):
        pass


def terminate_tree(pid):
    subprocess.run(
        ["taskkill.exe", "/PID", str(pid), "/T", "/F"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("baseline", "launch", "attach"), required=True)
    parser.add_argument("--firefox", type=pathlib.Path, required=True)
    parser.add_argument("--controller", type=pathlib.Path)
    parser.add_argument("--manifest", type=pathlib.Path)
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args()
    if args.mode != "baseline" and (not args.controller or not args.manifest):
        parser.error("launch and attach modes require --controller and --manifest")

    root = pathlib.Path(__file__).resolve().parents[1]
    page = (root / "testdata" / "validation.html").read_bytes()
    server = ResultServer(("127.0.0.1", 0), Handler, page)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    profile = pathlib.Path(tempfile.mkdtemp(prefix="firefox-detection-mem-patcher-"))
    (profile / "user.js").write_text(
        'user_pref("ui.primaryPointerCapabilities", 1);\n'
        'user_pref("ui.allPointerCapabilities", 1);\n'
        'user_pref("marionette.enabled", true);\n',
        encoding="utf-8",
    )
    url = f"http://127.0.0.1:{server.server_port}/"
    firefox_arguments = [
        "--headless",
        "--marionette",
        "-no-remote",
        "-profile",
        str(profile),
        url,
    ]
    if args.mode == "launch":
        command = [
            str(args.controller),
            "launch",
            "--firefox",
            str(args.firefox),
            "--manifest",
            str(args.manifest),
            "--",
            *firefox_arguments,
        ]
    else:
        command = [str(args.firefox), *firefox_arguments]

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
    )
    output = []
    firefox_pid = process.pid
    attach_process = None

    def collect_output():
        nonlocal firefox_pid
        for line in process.stdout:
            output.append(line.rstrip())
            if line.startswith("PROCESS_STARTED pid=") and firefox_pid == process.pid:
                firefox_pid = int(line.split()[1].split("=", 1)[1])

    output_thread = threading.Thread(target=collect_output, daemon=True)
    output_thread.start()
    try:
        result = server.result.get(timeout=args.timeout)
        if args.mode == "attach":
            baseline_expected = {
                "webdriver": True,
                "pointerFine": False,
                "pointerCoarse": True,
                "hover": False,
                "anyPointerFine": False,
                "anyPointerCoarse": True,
                "anyHover": False,
            }
            print("before=" + json.dumps(result, sort_keys=True))
            if result != baseline_expected:
                print("expected-before=" + json.dumps(baseline_expected, sort_keys=True))
                return 1
            attach_process = subprocess.Popen(
                [
                    str(args.controller),
                    "attach",
                    "--pid",
                    str(firefox_pid),
                    "--manifest",
                    str(args.manifest),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
            )
            deadline = time.monotonic() + args.timeout
            while time.monotonic() < deadline:
                line = attach_process.stdout.readline().rstrip()
                if line:
                    output.append(line)
                if line.startswith("INITIAL_SCAN_COMPLETE "):
                    break
                if attach_process.poll() is not None:
                    break
            else:
                print("timed out waiting for attach patch")
                return 1
            initial_output_length = len(output)

            def collect_attach_output():
                for line in attach_process.stdout:
                    output.append(line.rstrip())

            threading.Thread(target=collect_attach_output, daemon=True).start()
            server.reload.set()
            result = server.result.get(timeout=args.timeout)
            print("after=" + json.dumps(result, sort_keys=True))
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not any(
                line.startswith("APPLIED ") for line in output[initial_output_length:]
            ):
                time.sleep(0.05)
            if not any(line.startswith("APPLIED ") for line in output[initial_output_length:]):
                print("attach monitor did not observe a new content process")
                return 1
        expected = {
            "webdriver": args.mode == "baseline",
            "pointerFine": args.mode != "baseline",
            "pointerCoarse": args.mode == "baseline",
            "hover": args.mode != "baseline",
            "anyPointerFine": args.mode != "baseline",
            "anyPointerCoarse": args.mode == "baseline",
            "anyHover": args.mode != "baseline",
        }
        if args.mode != "attach":
            print(json.dumps(result, sort_keys=True))
        if result != expected:
            print("expected=" + json.dumps(expected, sort_keys=True))
            return 1
        if args.mode != "baseline" and not any(line.startswith("APPLIED ") for line in output):
            print("controller reported no applied patches")
            return 1
        if args.mode == "attach":
            repeated = subprocess.run(
                [
                    str(args.controller),
                    "attach",
                    "--pid",
                    str(firefox_pid),
                    "--manifest",
                    str(args.manifest),
                    "--once",
                ],
                capture_output=True,
                text=True,
                timeout=args.timeout,
                check=False,
            )
            if repeated.returncode or "ALREADY_APPLIED" not in repeated.stdout:
                print("idempotence validation failed")
                print(repeated.stdout)
                print(repeated.stderr)
                return 1
        print("integration validation passed")
        return 0
    except queue.Empty:
        print("timed out waiting for browser result")
        for line in output[-30:]:
            print(line)
        return 1
    finally:
        server.shutdown()
        if attach_process and attach_process.poll() is None:
            attach_process.send_signal(signal.CTRL_BREAK_EVENT)
            try:
                attach_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                attach_process.terminate()
        if process.poll() is None:
            if args.mode == "launch":
                process.send_signal(signal.CTRL_BREAK_EVENT)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.terminate()
            else:
                process.terminate()
        terminate_tree(firefox_pid)
        shutil.rmtree(profile, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
