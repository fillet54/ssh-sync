import base64
import paramiko

HOST = "Phillips-mac-mini.local"
USER = "phillip"
KEY  = "/path/to/id_rsa"  # or use password=... instead
PASSWORD = "IL0ve2Program!2"

# This is the code that will actually run on the remote side.
REMOTE_CODE = r"""

print("[remote] Script is running", flush=True)

print("[remote] Waiting for a line from stdin...", flush=True)

line = sys.stdin.readline().rstrip("\n")
print(f"[remote] Got line: {line}", flush=True)
"""

def main():
    # Encode the remote code so we can send it safely in the command string
    b64_code = base64.b64encode(REMOTE_CODE.encode("utf-8")).decode("ascii")

    # This command:
    #   1) decodes the base64 string into Python source
    #   2) execs that source in the global namespace
    cmd = (
        "python3 -u -c "
        f"'import base64,sys; "
        f"code = base64.b64decode(\"{b64_code}\"); "
        f"exec(code, globals())'"
    )

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(HOST, username=USER, password=PASSWORD)

    # Open a session and execute the command
    transport = ssh.get_transport()
    chan = transport.open_session()
    chan.exec_command(cmd)

    stdin  = chan.makefile("wb")
    stdout = chan.makefile("rb")
    stderr = chan.makefile_stderr("rb")

    # Read the first two lines the remote script prints
    print("[local] Reading remote output...")
    print(stdout.readline().decode("utf-8").rstrip())
    print(stdout.readline().decode("utf-8").rstrip())

    # Send a line to remote stdin
    print("[local] Sending a line to remote...")
    stdin.write(b"Hello from Paramiko!\n")
    stdin.flush()

    # Read the response
    print(stdout.readline().decode("utf-8").rstrip())

    # Close stdin to signal we're done
    stdin.close()

    # Optionally read any remaining stderr
    err = stderr.read().decode("utf-8")
    if err:
        print("[local] Remote stderr:")
        print(err)

    exit_status = chan.recv_exit_status()
    print(f"[local] Remote exited with status {exit_status}")

    ssh.close()

if __name__ == "__main__":
    main()
