#!/usr/bin/python3
"""Install inside the guest image only. One bounded request per disposable VM."""
import ctypes
import json
import os
import resource
import signal
import socket
import struct
import subprocess
import tempfile

MAX_FRAME = 32*1024*1024

def exact(sock, count):
    result = bytearray()
    while len(result) < count:
        part = sock.recv(min(count-len(result), 65536))
        if not part:
            raise ValueError('truncated frame')
        result.extend(part)
    return bytes(result)

def restrict():
    os.setgroups([])
    os.setgid(1000)
    os.setuid(1000)
    # PR_SET_NO_NEW_PRIVS; root recovery via setuid binaries is unavailable.
    if ctypes.CDLL(None).prctl(38, 1, 0, 0, 0) != 0:
        raise RuntimeError('cannot set no_new_privs')
    for kind, limit in ((resource.RLIMIT_CPU, 20), (resource.RLIMIT_AS, 512*1024*1024),
                        (resource.RLIMIT_FSIZE, 16*1024*1024), (resource.RLIMIT_NPROC, 16), (resource.RLIMIT_NOFILE, 32), (resource.RLIMIT_CORE, 0)):
        resource.setrlimit(kind, (limit, limit))

with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as listener:
    listener.bind((socket.VMADDR_CID_ANY, 5252))
    listener.listen(1)
    connection, _ = listener.accept()
    with connection:
        connection.settimeout(35)
        try:
            size = struct.unpack('!I', exact(connection, 4))[0]
            if size > MAX_FRAME:
                raise ValueError('frame too large')
            request = json.loads(exact(connection, size))
            if len(request['source'].encode()) > 64000:
                raise ValueError('source too large')
            with tempfile.TemporaryDirectory(dir='/tmp') as directory:
                os.chown(directory, 1000, 1000)
                source = directory+'/calculation.py'
                with open(source, 'w') as stream:
                    stream.write(request['source'])
                os.chmod(source, 0o444)
                # File-backed output prevents an untrusted stdout memory flood.
                with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
                    proc = subprocess.Popen(['/usr/bin/python3', '-I', source], cwd=directory,
                        env={'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'}, stdin=subprocess.PIPE,
                        stdout=out, stderr=err, preexec_fn=restrict, start_new_session=True)
                    try:
                        proc.communicate(json.dumps({'records': request['records']}).encode(), timeout=25)
                    finally:
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        proc.wait()
                    if proc.returncode != 0:
                        raise ValueError('calculation failed')
                    out.seek(0)
                    data = out.read(16*1024*1024+1)
                    if len(data) > 16*1024*1024:
                        raise ValueError('output exceeds quota')
                    candidate = json.loads(data)
                    if not isinstance(candidate, dict):
                        raise ValueError('candidate object required')
                    result = {'ok': True, 'candidate': candidate}
        except Exception:
            result = {'ok': False, 'reason': 'guest execution failed'}
        data = json.dumps(result, allow_nan=False).encode()
        connection.sendall(struct.pack('!I', len(data))+data)
