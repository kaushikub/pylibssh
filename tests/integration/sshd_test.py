"""Sanity tests for sshd-related helpers."""

import pathlib
import socket
import subprocess
import time
import typing as _t

import pytest
from _service_utils import make_sshd_command

from pylibsshext.errors import LibsshSessionException
from pylibsshext.session import Session


MAX_PORT_NUMBER = 65535
PERMISSIVE_MAX_AUTH_TRIES = 20
SSHD_TEST_USER = 'root'


@pytest.mark.usefixtures('ssh_client_session')
def test_sshd_addr_fixture_port(sshd_addr: tuple[str, int]) -> None:
    """Smoke-test sshd_addr fixture.

    # noqa: DAR101
    """
    _host, port = sshd_addr
    assert 0 < port <= MAX_PORT_NUMBER


def _port_accepts_connection(port: int, /) -> bool:
    """Check whether the given local port accepts a connection."""
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=0.1):
            return True
    except OSError:
        return False


def _wait_until_listening(
    *,
    sshd_proc: subprocess.Popen[bytes],
    port: int,
    timeout: float = 10,
) -> None:
    """Wait until the given local port accepts a connection."""
    deadline = time.monotonic() + timeout
    while not _port_accepts_connection(port):
        if sshd_proc.poll() is not None:
            msg = f'sshd exited with code {sshd_proc.returncode}'
            raise RuntimeError(msg)
        if time.monotonic() > deadline:
            msg = 'sshd did not start listening'
            raise TimeoutError(msg) from None
        time.sleep(0.1)


def _start_test_sshd(
    *,
    hostkey_path: pathlib.Path,
    pid_file: pathlib.Path,
    port: int,
    max_auth_tries: int,
) -> subprocess.Popen[bytes]:
    """Spawn an sshd that advertises every authentication method."""
    sshd_cmd = make_sshd_command(
        hostkey_path=hostkey_path,
        pid_file=pid_file,
        port=port,
        extra_opts=(
            '-oPasswordAuthentication=yes',
            '-oKbdInteractiveAuthentication=yes',
            '-oGSSAPIAuthentication=yes',
            '-oPubkeyAuthentication=yes',
            f'-oMaxAuthTries={max_auth_tries}',
        ),
    )
    sshd_proc = subprocess.Popen(sshd_cmd)
    try:
        _wait_until_listening(sshd_proc=sshd_proc, port=port)
    except Exception:
        _stop_test_sshd(sshd_proc=sshd_proc)
        raise
    return sshd_proc


def _stop_test_sshd(
    *,
    sshd_proc: subprocess.Popen[bytes],
    timeout: float = 10,
) -> None:
    """Terminate an sshd spawned by _start_test_sshd."""
    sshd_proc.terminate()
    try:
        sshd_proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        sshd_proc.kill()
        sshd_proc.wait()


@pytest.fixture
def permissive_auth_sshd_addr(
    free_port_num: int,
    sshd_hostkey_path: pathlib.Path,
    sshd_path: pathlib.Path,
) -> _t.Iterator[tuple[str, int]]:
    """Spawn an sshd that allows many authentication attempts."""
    sshd_proc = _start_test_sshd(
        hostkey_path=sshd_hostkey_path,
        pid_file=sshd_path / 'test-sshd.pid',
        port=free_port_num,
        max_auth_tries=PERMISSIVE_MAX_AUTH_TRIES,
    )
    yield ('127.0.0.1', free_port_num)
    _stop_test_sshd(sshd_proc=sshd_proc)


@pytest.fixture
def disconnecting_sshd_addr(
    free_port_num: int,
    sshd_hostkey_path: pathlib.Path,
    sshd_path: pathlib.Path,
) -> _t.Iterator[tuple[str, int]]:
    """Spawn an sshd that disconnects after the first failed authentication."""
    sshd_proc = _start_test_sshd(
        hostkey_path=sshd_hostkey_path,
        pid_file=sshd_path / 'test-sshd.pid',
        port=free_port_num,
        max_auth_tries=1,
    )
    yield ('127.0.0.1', free_port_num)
    _stop_test_sshd(sshd_proc=sshd_proc)


def test_connect_all_auth_methods_fail_raises(
    permissive_auth_sshd_addr: tuple[str, int],
    tmp_path: pathlib.Path,
) -> None:
    """Check that exhausting every authentication method raises."""
    untrusted_key_path = tmp_path / 'untrusted_ecdsa_key'
    keygen_cmd = (
        'ssh-keygen',
        '-qtecdsa',
        '-b256',
        '-N',
        '',
        f'-f{untrusted_key_path!s}',
    )
    subprocess.check_call(keygen_cmd, stdin=subprocess.DEVNULL)

    ssh_session = Session()
    incorrect_password = 'incorrect-password'  # noqa: S105  # wrong on purpose
    with pytest.raises(
        LibsshSessionException,
        match='acceptable way to authenticate',
    ):
        ssh_session.connect(
            host=permissive_auth_sshd_addr[0],
            port=permissive_auth_sshd_addr[1],
            user=SSHD_TEST_USER,
            password=incorrect_password,
            private_key=untrusted_key_path.read_bytes(),
            host_key_checking=False,
        )


def test_connect_disconnect_during_auth_raises(
    disconnecting_sshd_addr: tuple[str, int],
) -> None:
    """Check that a server disconnect during authentication raises."""
    ssh_session = Session()
    incorrect_password = 'wrong-password'  # noqa: S105  # wrong on purpose
    with pytest.raises(
        LibsshSessionException,
        match='Session was disconnected',
    ):
        ssh_session.connect(
            host=disconnecting_sshd_addr[0],
            port=disconnecting_sshd_addr[1],
            user=SSHD_TEST_USER,
            password=incorrect_password,
            host_key_checking=False,
        )
