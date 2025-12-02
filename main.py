import base64
import hashlib
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
import hashlib
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


def send_packet(name: str, payload: bytes):
    sha_hex = hashlib.sha1(payload).hexdigest()
    header = f"{sha_hex} {len(payload)} {name}\n".encode("utf-8")
    sys.stdout.buffer.write(header)
    if payload:
        sys.stdout.buffer.write(payload)
    sys.stdout.buffer.flush()


def _read_exact(fin, length: int) -> bytes:
    data = b""
    while len(data) < length:
        chunk = fin.read(length - len(data))
        if not chunk:
            raise EOFError("unexpected EOF while reading payload")
        data += chunk
    return data


def recv_packet():
    header = sys.stdin.buffer.readline()
    if not header:
        return None
    try:
        sha_hex, length_str, name = header.decode("utf-8").rstrip("\n").split(" ", 2)
        length = int(length_str)
    except ValueError:
        raise RuntimeError(f"invalid header line: {header!r}")
    payload = _read_exact(sys.stdin.buffer, length) if length else b""
    if hashlib.sha1(payload).hexdigest() != sha_hex:
        raise RuntimeError(f"sha mismatch for packet {name}")
    return name, payload


def parse_manifest_payload(payload: bytes):
    lines = payload.decode("utf-8").splitlines()
    if not lines:
        raise RuntimeError("empty manifest payload")
    count = int(lines[0])
    entries = []
    for line in lines[1:1 + count]:
        sha, mode_str, path = line.split(" ", 2)
        entries.append({"path": path, "sha1": sha, "mode": int(mode_str, 8)})
    if len(entries) != count:
        raise RuntimeError("manifest count mismatch")
    return entries


def encode_need_files(paths, extras):
    lines = [f"{len(paths)} {len(extras)}"]
    lines.extend(paths)
    lines.extend(extras)
    return "\n".join(lines).encode("utf-8")


def ensure_parent(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)


def write_file(root: Path, rel_path: str, data: bytes, mode: Optional[int]):
    dest = root / rel_path
    ensure_parent(dest)
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

    send_packet("ready", root.as_posix().encode("utf-8"))

    manifest_packet = recv_packet()
    if manifest_packet is None or manifest_packet[0] != "manifest":
        send_packet("error", b"expected manifest")
        return
    host_files = parse_manifest_payload(manifest_packet[1])

    host_map = {item["path"]: item for item in host_files}

    remote_manifest = build_manifest(root)
    remote_map = {item["path"]: item for item in remote_manifest}

    needed = []
    for path, item in host_map.items():
        remote_item = remote_map.get(path)
        if remote_item is None or remote_item.get("sha1") != item.get("sha1"):
            needed.append(path)

    extras = [path for path in remote_map.keys() if path not in host_map]

    send_packet("need_files", encode_need_files(needed, extras))

    received = set()
    while True:
        msg = recv_packet()
        if msg is None:
            break
        name, payload = msg
        if name == "sync_done":
            break

        rel = name
        mode = host_map.get(rel, {}).get("mode")
        write_file(root, rel, payload, mode)
        received.add(rel)
        send_packet("file_written", rel.encode("utf-8"))

    # Clean up files that do not exist on the host so the directory mirrors.
    remove_extras(root, set(host_map.keys()))
    complete_paths = sorted(received)
    lines = [str(len(complete_paths)), *complete_paths]
    send_packet("complete", "\n".join(lines).encode("utf-8"))


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


def send_packet(fh, name: str, payload: bytes):
    sha_hex = hashlib.sha1(payload).hexdigest()
    header = f"{sha_hex} {len(payload)} {name}\n".encode("utf-8")
    fh.write(header)
    if payload:
        fh.write(payload)
    fh.flush()


def _read_exact(fh, length: int) -> bytes:
    data = b""
    while len(data) < length:
        chunk = fh.read(length - len(data))
        if not chunk:
            raise EOFError("unexpected EOF while reading payload")
        data += chunk
    return data


def recv_packet(fh):
    header = fh.readline()
    if not header:
        return None
    try:
        sha_hex, length_str, name = header.decode("utf-8").rstrip("\n").split(" ", 2)
        length = int(length_str)
    except ValueError:
        raise RuntimeError(f"invalid header line: {header!r}")
    payload = _read_exact(fh, length) if length else b""
    if hashlib.sha1(payload).hexdigest() != sha_hex:
        raise RuntimeError(f"sha mismatch for packet {name}")
    return name, payload


def encode_manifest(files):
    lines = [str(len(files))]
    for item in files:
        mode_str = format(item["mode"], "o")
        lines.append(f"{item['sha1']} {mode_str} {item['path']}")
    return "\n".join(lines).encode("utf-8")


def parse_need_files(payload: bytes):
    lines = payload.decode("utf-8").splitlines()
    if not lines:
        return [], []
    first = lines[0].split()
    if len(first) != 2:
        raise RuntimeError("invalid need_files header")
    path_count, extra_count = map(int, first)
    paths = lines[1:1 + path_count]
    extras_start = 1 + path_count
    extras = lines[extras_start:extras_start + extra_count]
    return paths, extras


def parse_complete(payload: bytes):
    lines = payload.decode("utf-8").splitlines()
    if not lines:
        return []
    count = int(lines[0])
    updated = lines[1:1 + count]
    return updated


def sync_directory(local_dir: Path, remote_dir: str, ssh: paramiko.SSHClient):
    manifest = build_manifest(local_dir)
    chan, stdin, stdout, stderr = run_remote_session(ssh, remote_dir)

    ready = recv_packet(stdout)
    if ready is None or ready[0] != "ready":
        raise RuntimeError("remote did not signal readiness")
    ready_root = ready[1].decode("utf-8")

    send_packet(stdin, "manifest", encode_manifest(manifest))
    response = recv_packet(stdout)
    if response is None or response[0] != "need_files":
        raise RuntimeError("remote did not request files")
    needed, extras = parse_need_files(response[1])

    print(f"Remote root: {ready_root}")
    if extras:
        print(f"Remote will remove {len(extras)} extra file(s): {extras}")

    for rel_path in needed:
        path = local_dir / rel_path
        payload = path.read_bytes()
        send_packet(stdin, rel_path, payload)
        ack = recv_packet(stdout)
        if ack is None or ack[0] != "file_written":
            raise RuntimeError(f"failed to write {rel_path}")
        ack_path = ack[1].decode("utf-8")
        if ack_path != rel_path:
            raise RuntimeError(f"unexpected ack for {ack_path}")

    send_packet(stdin, "sync_done", b"")
    complete = recv_packet(stdout)
    if complete is None or complete[0] != "complete":
        raise RuntimeError("sync did not complete")
    updated = parse_complete(complete[1])
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
