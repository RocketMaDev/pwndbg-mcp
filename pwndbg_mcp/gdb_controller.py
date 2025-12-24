from dataclasses import dataclass
from pygdbmi.gdbcontroller import GdbController
import asyncio
from concurrent.futures import ThreadPoolExecutor
import logging
import os
import select
import pty
import tty
import termios
from hexdump import hexdump
from enum import StrEnum
import re
ANSI_COLOR_RE = re.compile(r'\x1b\[[0-9;]*m')

logger = logging.getLogger(__name__)

class GdbState(StrEnum):
    DEAD    = 'Uninitialized'
    STOPPED = 'Stopped'
    RUNNING = 'Running'

class GdbMIType(StrEnum):
    NOTIFY  = 'notify'
    CONSOLE = 'console'
    LOG     = 'log'
    RESULT  = 'result'
    TARGET  = 'target'

@dataclass
class GdbResponse:
    """Parsed GDB/MI response."""
    mitype: GdbMIType
    message: str | dict | None

    def __init__(self, mitype: str, message: str | None, payload: dict | str | None) -> None:
        self.mitype = GdbMIType(mitype)
        self.message = message if message else payload
        if isinstance(self.message, str): # strip color
            self.message = ANSI_COLOR_RE.sub('', self.message)


def update_gdb_state(resps: list[GdbResponse]) -> GdbState | None:
    """Parse messages from resps to see if gdb state need to update.

    Returns:
        GdbState if found state (return the last state) or None if not found
    """
    cache = None
    for resp in resps:
        if resp.mitype is GdbMIType.NOTIFY:
            match resp.message:
                case 'running': cache = GdbState.RUNNING
                case 'stopped': cache = GdbState.STOPPED
    return cache


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

        # save original slave attr, except ECHO, so we can restore it when sending signal
        self._pty_attrs: termios._Attr = termios.tcgetattr(self._pty_slave)
        self._pty_attrs[3] &= ~termios.ECHO
        tty.setraw(self._pty_slave)
        tty.setraw(self._pty_master)

        self.poller = select.poll()
        self.poller.register(self._pty_master, select.EPOLLIN)
        # Start GDB
        command = [self.gdb_path, *self.gdb_args, '-ex', f'set inferior-tty {self._pty_name}']
        print(command)
        loop = asyncio.get_event_loop()
        self._controller = await loop.run_in_executor(
            self._executor,
            lambda: GdbController(command=command),
        )
        self.state = GdbState.STOPPED
        self._started = True
        logger.info(f"GDB started with PTY: {self._pty_name}")

    async def execute(
        self,
        command: str,
        timeout: float | None = None,
    ) -> list[GdbResponse] | None:
        """Execute GDB/MI command asynchronously.

        Args:
            command: GDB/MI command to execute
            timeout: Command timeout in seconds (None for default)

        Returns:
            List of parsed GDB responses or None if gdb is waiting

        Raises:
            RuntimeError: If controller not started
        """
        loop = asyncio.get_event_loop()
        parsed_responses = []
        if self.state is GdbState.RUNNING:
            # perhaps user trigger interupt to stop tracee?
            responses = await loop.run_in_executor(
                self._executor,
                lambda: self._controller.get_gdb_response(1, False)
            )
            parsed_responses = [
                GdbResponse(r['type'], r['message'], r['payload']) for r in responses
            ]
            if new_state := update_gdb_state(parsed_responses):
                self.state = new_state
                logger.debug(f'New state: {self.state}')

        if self.state is not GdbState.STOPPED:
            return None

        timeout_sec = timeout if timeout is not None else self.timeout

        logger.debug(f"Executing GDB command: {command}")

        # Execute in thread pool and parse responses inline
        try:
            responses = await loop.run_in_executor(
                self._executor,
                lambda: self._controller.write(command, timeout_sec, raise_error_on_timeout=False),
            )
        except BrokenPipeError:
            # gdb exited! restart it next time
            self.state = GdbState.DEAD
            return [GdbResponse('result', 'GDB exited! run this command again', None)]

        parsed_responses.extend(
            GdbResponse(r['type'], r['message'], r['payload']) for r in responses
        )

        # merge disconnected lines and remove \n
        cache = ''
        pop_list = []
        for i, r in enumerate(parsed_responses):
            match r.mitype:
                case GdbMIType.CONSOLE:
                    if not r.message.endswith('\n'):
                        cache += r.message
                        pop_list.append(i)
                    else:
                        if cache:
                            r.message = cache + r.message
                            cache = ''
                        r.message = r.message.strip()
                case GdbMIType.LOG:
                    r.message = r.message.strip()
                case GdbMIType.NOTIFY:
                    if r.message == 'cmd-param-changed':
                        pop_list.append(i)
                case GdbMIType.RESULT:
                    pop_list.append(i)
        if cache:
            parsed_responses[pop_list[-1]].message = cache.strip()
            pop_list.pop(-1)
        for i in reversed(pop_list):
            parsed_responses.pop(i)

        if new_state := update_gdb_state(parsed_responses):
            self.state = new_state
            logger.debug(f'New state: {self.state}')

        for r in parsed_responses:
            logger.info(f'MSG: {r.mitype:9s} {r.message!r}')

        if command == 'quit' or command == 'q':
            # identify quit to handle it
            await self.close()
        return parsed_responses


    async def send_to_process(self, data: bytes) -> None:
        """Send data to the target process through PTY.

        Args:
            data: String to send to the process
        """
        if not self._pty_master:
            raise RuntimeError("PTY not available")

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: os.write(self._pty_master, data)
        )
        logger.debug(f"Sent to process: {data}")

    async def interrupt_process(self, ctrl: bytes) -> None:
        """Interrupt target process by sending \\x03 to pty
        """
        if not self._pty_master:
            raise RuntimeError("PTY not available")

        def _send_ctrl():
            try:
                termios.tcsetattr(self._pty_slave, termios.TCSANOW, self._pty_attrs)
                logger.info(f'Sent {ctrl} to slave')
                os.write(self._pty_master, ctrl)
            finally:
                tty.setraw(self._pty_slave)

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _send_ctrl)
        logger.debug('Interrupting process')

    async def read_from_process(self, size: int = 4096, timeout: int = 5) -> str | None:
        """Read data from the target process through PTY using poll.

        Args:
            size: Maximum bytes to read
            timeout: Read timeout in secconds

        Returns:
            Data read from process, or empty string on timeout/no data
        """
        loop = asyncio.get_event_loop()

        def _read():
            try:
                return os.read(self._pty_master, size) if self.poller.poll(timeout * 1000) else b''
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
        if not self._started:
            return
        try:
            if self._controller:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(
                    self._executor,
                    self._controller.exit,
                )
                self._controller = None
                self._started = False
                logger.info("GDB controller closed")
        finally:
            # Close PTY
            if self._pty_master:
                os.close(self._pty_master)
                self._pty_master = None
            if self._pty_slave:
                os.close(self._pty_slave)
                self._pty_slave = None

        self._executor.shutdown(wait=True)
        self.state = GdbState.DEAD
