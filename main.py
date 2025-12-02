import base64
import hashlib
import json
import os
import shlex
from pathlib import Path
from typing import Optional

import paramiko
from docopt import docopt

HOST = "Phillips-mac-mini.local"
USER = "phillip"
KEY = None  # "/path/to/id_rsa"
PASSWORD = "IL0ve2Program!2"


# Remote-side logic: receive a manifest, compute the remote manifest, request
# changed/missing files, accept file transfers, optionally remove extraneous
# files, and report completion.
REMOTE_CODE = r"""
import base64
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Optional


def sha1sum(path: Path) -> str:
    h = hashlib.sha1()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def build_manifest(root: Path):
    entries = []
    for file_path in root.rglob("*"):
        if file_path.is_file():
            rel = file_path.relative_to(root).as_posix()
            st = file_path.stat()
            entries.append(
                {"path": rel, "sha1": sha1sum(file_path), "mode": int(st.st_mode & 0o777)}
            )
    return entries


def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def recv():
    line = sys.stdin.readline()
    if not line:
        return None
    return json.loads(line)


def ensure_parent(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)


def write_file(root: Path, rel_path: str, payload: str, mode: Optional[int]):
    dest = root / rel_path
    ensure_parent(dest)
    data = base64.b64decode(payload)
    with dest.open("wb") as fh:
        fh.write(data)
    if mode is not None:
        dest.chmod(mode)


def remove_extras(root: Path, keep_paths):
    for file_path in sorted(root.rglob("*"), reverse=True):
        if file_path.is_file() and file_path.relative_to(root).as_posix() not in keep_paths:
            try:
                file_path.unlink()
            except OSError:
                pass
        if file_path.is_dir() and not any(file_path.iterdir()):
            try:
                file_path.rmdir()
            except OSError:
                pass


def main(remote_root: str):
    root = Path(remote_root).expanduser()
    if not root.is_absolute():
        root = Path.home() / root
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=True)

    send({"event": "ready", "root": root.as_posix()})

    manifest_msg = recv()
    if manifest_msg is None or manifest_msg.get("type") != "manifest":
        send({"event": "error", "message": "expected manifest"})
        return

    host_files = manifest_msg["files"]
    host_map = {item["path"]: item for item in host_files}

    remote_manifest = build_manifest(root)
    remote_map = {item["path"]: item for item in remote_manifest}

    needed = []
    for path, item in host_map.items():
        remote_item = remote_map.get(path)
        if remote_item is None or remote_item.get("sha1") != item.get("sha1"):
            needed.append(path)

    extras = [path for path in remote_map.keys() if path not in host_map]

    send({"event": "need_files", "paths": needed, "extras": extras})

    received = set()
    while True:
        msg = recv()
        if msg is None:
            break
        if msg.get("type") == "file":
            rel = msg["path"]
            write_file(root, rel, msg["data"], msg.get("mode"))
            received.add(rel)
            send({"event": "file_written", "path": rel})
        elif msg.get("type") == "sync_done":
            break

    # Clean up files that do not exist on the host so the directory mirrors.
    remove_extras(root, set(host_map.keys()))
    send({"event": "complete", "updated": sorted(received)})


if __name__ == "__main__":
    main(sys.argv[1])
"""


USAGE = """Usage:
  main.py <local_dir> <remote_dir> [--host=<host>] [--user=<user>] [--password=<pwd>] [--key=<key>]

Options:
  --host=<host>       Remote host to connect to.
  --user=<user>       SSH username.
  --password=<pwd>    SSH password.
  --key=<key>         Path to SSH private key.
"""


def sha1sum(path: Path) -> str:
    h = hashlib.sha1()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def build_manifest(root: Path):
    entries = []
    for file_path in root.rglob("*"):
        if file_path.is_file():
            rel = file_path.relative_to(root).as_posix()
            st = file_path.stat()
            entries.append(
                {"path": rel, "sha1": sha1sum(file_path), "mode": int(st.st_mode & 0o777)}
            )
    return entries


def encode_file(path: Path) -> str:
    data = path.read_bytes()
    return base64.b64encode(data).decode("ascii")


def connect(host: str, user: str, password: Optional[str], key_path: Optional[str]) -> paramiko.SSHClient:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username=user, password=password, key_filename=key_path)
    return ssh


def run_remote_session(ssh: paramiko.SSHClient, remote_dir: str):
    b64_code = base64.b64encode(REMOTE_CODE.encode("utf-8")).decode("ascii")
    cmd = (
        "python3 -u -c "
        f"'import base64,sys; code = base64.b64decode(\"{b64_code}\"); "
        f"exec(code, globals())' "
        f"{shlex.quote(remote_dir)}"
    )

    transport = ssh.get_transport()
    chan = transport.open_session()
    chan.exec_command(cmd)

    stdin = chan.makefile("wb")
    stdout = chan.makefile("rb")
    stderr = chan.makefile_stderr("rb")
    return chan, stdin, stdout, stderr


def send_json(fh, obj):
    fh.write((json.dumps(obj) + "\n").encode("utf-8"))
    fh.flush()


def recv_json(fh):
    line = fh.readline()
    if not line:
        return None
    return json.loads(line.decode("utf-8"))


def sync_directory(local_dir: Path, remote_dir: str, ssh: paramiko.SSHClient):
    manifest = build_manifest(local_dir)
    chan, stdin, stdout, stderr = run_remote_session(ssh, remote_dir)

    ready = recv_json(stdout)
    if ready is None or ready.get("event") != "ready":
        raise RuntimeError("remote did not signal readiness")

    send_json(stdin, {"type": "manifest", "files": manifest})
    response = recv_json(stdout)
    if response is None or response.get("event") != "need_files":
        raise RuntimeError("remote did not request files")

    needed = response.get("paths", [])
    extras = response.get("extras", [])

    print(f"Remote root: {ready.get('root')}")
    if extras:
        print(f"Remote will remove {len(extras)} extra file(s): {extras}")

    for rel_path in needed:
        path = local_dir / rel_path
        payload = encode_file(path)
        mode = int(path.stat().st_mode & 0o777)
        send_json(stdin, {"type": "file", "path": rel_path, "data": payload, "mode": mode})
        ack = recv_json(stdout)
        if ack is None or ack.get("event") != "file_written":
            raise RuntimeError(f"failed to write {rel_path}")

    send_json(stdin, {"type": "sync_done"})
    complete = recv_json(stdout)
    if complete is None or complete.get("event") != "complete":
        raise RuntimeError("sync did not complete")
    updated = complete.get("updated", [])
    print(f"Updated {len(updated)} file(s): {updated}")

    stdin.close()
    err = stderr.read().decode("utf-8")
    if err:
        print("[remote stderr]", err)
    exit_status = chan.recv_exit_status()
    if exit_status:
        raise RuntimeError(f"remote exited with status {exit_status}")


def main():
    args = docopt(USAGE)
    local_dir = Path(args["<local_dir>"]).expanduser().resolve()
    if not local_dir.exists() or not local_dir.is_dir():
        raise SystemExit(f"Local path {local_dir} is not a directory")

    remote_dir = args["<remote_dir>"]
    host = args.get("--host") or HOST
    user = args.get("--user") or USER
    password = args.get("--password") or PASSWORD
    key_path = args.get("--key") or KEY

    ssh = connect(host, user, password, key_path)
    try:
        sync_directory(local_dir, remote_dir, ssh)
    finally:
        ssh.close()


if __name__ == "__main__":
    main()
