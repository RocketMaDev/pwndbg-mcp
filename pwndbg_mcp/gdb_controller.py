from dataclasses import dataclass
from pygdbmi.gdbcontroller import GdbController
import asyncio
from concurrent.futures import ThreadPoolExecutor
import logging
import os
import select
import pty
from hexdump import hexdump
from enum import StrEnum

logger = logging.getLogger(__name__)

class GdbState(StrEnum):
    DEAD = 'Uninitialized'
    STOPPED = 'Stopped'
    RUNNING = 'Running'


@dataclass
class GdbResponse:
    """Parsed GDB/MI response."""
    type: str  # result/console/log/notify/target
    message: str | None
    payload: dict[str, any] | None
    token: int | None


class AsyncGdbController:
    state: GdbState

    def __init__(self, gdb_path: str, gdb_args: list[str] | None = None, timeout: float = 5):
        self.gdb_path = gdb_path
        self.gdb_args = gdb_args or ["-q", "--interpreter=mi3"]
        self.timeout = timeout
        self._controller: GdbController | None = None
        self._executor = ThreadPoolExecutor(max_workers=1)
        self.state = GdbState.DEAD

        # PTY for target process I/O
        self._pty_master: int | None = None
        self._pty_slave: int | None = None
        self._pty_name: str | None = None

    async def start(self) -> None:
        if self.state is not GdbState.DEAD:
            return

        # Create PTY for target process communication
        self._pty_master, self._pty_slave = pty.openpty()
        self._pty_name = os.ttyname(self._pty_slave)
        logger.debug(f"Created PTY: master={self._pty_master}, slave={self._pty_name}")

        self.poller = select.poll()
        self.poller.register(self._pty_master, select.EPOLLIN)
        # Start GDB
        loop = asyncio.get_event_loop()
        self._controller = await loop.run_in_executor(
            self._executor,
            lambda: GdbController(command=[self.gdb_path, *self.gdb_args,
                                           '-ex', f'set inferior-tty {self._pty_name}']),
        )
        self.state = GdbState.STOPPED
        logger.info(f"GDB started with PTY: {self._pty_name}")

    async def execute(
        self,
        command: str,
        timeout: float | None = None,
        raise_error: bool = True
    ) -> list[GdbResponse] | None:
        """Execute GDB/MI command asynchronously.

        Args:
            command: GDB/MI command to execute
            timeout: Command timeout in seconds (None for default)
            raise_error: Whether to raise exception on error

        Returns:
            List of parsed GDB responses

        Raises:
            RuntimeError: If controller not started
            Exception: If command fails and raise_error is True
        """
        if self.state is not GdbState.STOPPED:
            return None

        loop = asyncio.get_event_loop()
        timeout_sec = timeout if timeout is not None else self.timeout

        logger.debug(f"Executing GDB command: {command}")

        # Execute in thread pool and parse responses inline
        responses = await loop.run_in_executor(
            self._executor,
            lambda: self._controller.write(command, timeout_sec=timeout_sec),
        )

        logging.info(responses)
        parsed_responses = [
            GdbResponse(
                type=r.get("type"),
                message=r.get("message"),
                payload=r.get("payload"),
                token=r.get("token"),
            )
            for r in responses
        ]

        # Error handling
        if raise_error:
            for resp in parsed_responses:
                if resp.type == "result" and resp.message == "error":
                    error_msg = resp.payload.get("msg", "Unknown GDB error") if resp.payload else "Unknown GDB error"
                    raise Exception(f"GDB error: {error_msg}")

        return parsed_responses


    async def send_to_process(self, data: str) -> None:
        """Send data to the target process through PTY.

        Args:
            data: String to send to the process
        """
        if not self._pty_master:
            raise RuntimeError("PTY not available")

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: os.write(self._pty_master, data.encode())
        )
        logger.debug(f"Sent to process: {data!r}")

    async def read_from_process(self, size: int = 4096, timeout: int = 5000) -> str | None:
        """Read data from the target process through PTY using poll.

        Args:
            size: Maximum bytes to read
            timeout: Read timeout in seconds

        Returns:
            Data read from process, or empty string on timeout/no data
        """
        loop = asyncio.get_event_loop()

        def _read():
            try:
                return os.read(self._pty_master, size) if self.poller.poll(timeout) else b''
            except OSError:
                return b''

        data = await loop.run_in_executor(None, _read)
        if not data:
            logger.debug('Process has no output currently')
            return None
        if all(b >= 32 or b == 0xd or b == 0xa for b in data):
            try:
                result = data.decode('utf-8')
            except UnicodeDecodeError as _:
                result = hexdump(data, 'return')
        else:
            result = hexdump(data, 'return')
        logger.debug(f"Read from process: {result!r}")
        return result

    async def close(self) -> None:
        if self.state is GdbState.DEAD:
            return

        if self._controller:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                self._executor,
                self._controller.exit,
            )
            self._controller = None
            self._started = False
            logger.info("GDB controller closed")

        # Close PTY
        if self._pty_master:
            os.close(self._pty_master)
            self._pty_master = None
        if self._pty_slave:
            os.close(self._pty_slave)
            self._pty_slave = None

        self._executor.shutdown(wait=True)
        self.state = GdbState.DEAD
