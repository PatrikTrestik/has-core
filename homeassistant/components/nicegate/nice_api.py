"""API for Nice gate WiFi interface."""
import asyncio
import base64
import hashlib
import logging
import random
import re
import ssl

import defusedxml.ElementTree as ET

BUFF_SIZE = 512
_LOGGER = logging.getLogger("nicegate")


class NiceGateApi:
    """API for Nice Gate communication."""

    def __init__(self, host, mac, username, pwd):
        """Initialize API for Nice gate."""
        self.host = host
        self.target = mac
        self.source = "python"
        self.username = username
        self.descr = "Home assistant integration"
        self.pwd = pwd
        # Client challenge, randomly generated
        self.client_challenge = f"{random.randint(1, 9999999):08x}".upper()
        # Server challenge, send by server
        self.server_challenge = ""
        self.command_sequence = 1
        self.command_id = 0
        self.session_id = 1
        self.connection = False
        self.gate_status = None
        self.serv_reader: asyncio.StreamReader = None
        self.serv_writer: asyncio.StreamWriter = None
        self.update_callback = None

    def set_update_callback(self, callback):
        """Register callback for update notification."""
        self.update_callback = callback

    async def get_status(self):
        """Get current status of gate."""
        if self.gate_status is None:
            await self.status()
        return self.gate_status

    # Translate hex string to byte array
    def __hex_to_bytearray(self, hex_str):
        return bytes.fromhex(hex_str)

    # Get sha256
    def __sha256(self, *args):
        hsh = hashlib.sha256()
        for arg in args:
            hsh.update(arg)
        return hsh.digest()

    # Invert byte array
    def __invert_array(self, data):
        return data[::-1]

    # Generating command ID from session ID
    def __generate_command_id(self, session_id):
        i = self.command_sequence
        self.command_sequence = i + 1
        return (i << 8) | (int(session_id) & 255)

    # Build sign for message
    def __build_signature(self, xml_command):
        client_challenge = self.__hex_to_bytearray(self.client_challenge)
        server_challenge = self.__hex_to_bytearray(self.server_challenge)

        pairing_password = base64.b64decode(self.pwd)
        session_password = self.__sha256(
            pairing_password,
            self.__invert_array(server_challenge),
            self.__invert_array(client_challenge),
        )

        msg_hash = self.__sha256(xml_command.encode())
        sign = self.__sha256(msg_hash, session_password)
        return "<Sign>" + base64.b64encode(sign).decode("utf-8") + "</Sign>"

    # Check if sign needed
    def __is_sign_needed(self, command_type):
        if command_type in ("CONFIG", "VERIFY", "CONNECT", "PAIR"):
            return False
        return True

    # Wrap message, protocol needed
    def __wrap_message(self, xml: str) -> bytes:
        _LOGGER.debug(xml)
        return ("\u0002" + xml + "\u0003").encode()

    async def __recvloop(self):
        try:
            while True:
                msg = await self.__recvall()
                if msg == "":
                    await self.connect()
                    break
                await self.__process_event(msg)
        except OSError as err_msg:
            _LOGGER.error(err_msg)
            return

    # Get all data from socket
    async def __recvall(self):
        data = b""
        while True:
            try:
                part = await self.serv_reader.read(BUFF_SIZE)
            except OSError as error_msg:
                # a "real" error occurred
                _LOGGER.error(error_msg)
                break
            else:
                data += part
                if re.search(b"\x02", data):
                    data = data[1:]
                if re.search(b"\x03", data):
                    data = data[:-1]
                    _LOGGER.debug(data)
                    break
        answer = data.decode()
        self.__find_session_id(answer)
        return answer

    def __find_session_id(self, msg):
        """Find Session ID in response, SessionID used for MessageID generating."""
        match = re.search(r'Authentication\sid=[\'"]?([^\'" >]+)', msg)
        if match:
            self.session_id = match.group(1)

    def __find_server_challenge(self, msg):
        """Find server challenge in response, needed of message signature."""
        match = re.search(r'sc=[\'"]?([^\'" >]+)', msg)
        if match:
            self.server_challenge = match.group(1)
        else:
            _LOGGER.warning("No server challenge found")

    async def __build_message(self, command_type, body):
        """Build request."""
        self.command_id = self.__generate_command_id(self.session_id)
        start_request = '<Request id="{}" source="{}" target="{}" gw="gwID" protocolType="NHK" protocolVersion="1.0" type="{}">\r\n'.format(
            self.command_id, self.source, self.target, command_type
        )
        end_request = "</Request>\r\n"
        msg = self.__wrap_message(
            start_request
            + body
            + (
                self.__build_signature(start_request + body)
                if self.__is_sign_needed(command_type)
                else ""
            )
            + end_request
        )
        _LOGGER.debug(msg)
        self.serv_writer.write(msg)
        await self.serv_writer.drain()

    async def __process_event(self, msg):
        resp = ET.fromstring(msg)
        if resp.tag == "Event":
            if resp.attrib["type"] == "CHANGE":
                self.gate_status = resp.findtext(
                    "./Devices/Device/Properties/DoorStatus"
                )
                _LOGGER.info("Event CHANGE received %s", self.gate_status)
                if self.update_callback is not None:
                    await self.update_callback()
        if resp.tag == "Response":
            if resp.attrib["type"] == "STATUS":
                self.gate_status = resp.findtext(
                    "./Devices/Device/Properties/DoorStatus"
                )
                _LOGGER.info("Status received %s", self.gate_status)
                if self.update_callback is not None:
                    await self.update_callback()

    async def connect(self):
        """Connect to IT4WIFI."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
        ctx.check_hostname = False
        # self.serv = ctx.wrap_socket(
        #     socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # )
        # self.serv.connect((self.host, 443))
        reader, writer = await asyncio.open_connection(self.host, 443, ssl=ctx)
        self.serv_reader = reader
        self.serv_writer = writer

        await self.__build_message("VERIFY", f'<User username="{self.username}"/>')
        verify = await self.__recvall()
        if re.search(r'Authentication\sid=[\'"]?([^\'" >]+)', verify):
            await self.__build_message(
                "CONNECT",
                '<Authentication username="{}" cc="{}"/>'.format(
                    self.username, self.client_challenge
                ),
            )
            connect = await self.__recvall()
            self.__find_server_challenge(connect)
            self.connection = True
            # start loop
            asyncio.create_task(self.__recvloop())
            return True

        _LOGGER.warning("No user found")
        self.connection = False
        return False

    async def status(self, cmd="STATUS"):
        """Get IT4WIFI status."""
        if not self.connection:
            await self.connect()
        await self.__build_message(cmd, "")

    async def change(self, command):
        """Open, close or stop gates."""
        if not self.connection:
            await self.connect()
        await self.__build_message(
            "CHANGE",
            '<Devices><Device id="1">\n<Services><DoorAction>{}</DoorAction>\n</Services ></Device></Devices>'.format(
                command
            ),
        )

    async def check(self):
        """Ping for prevent sokcet close."""
        if not self.connection:
            await self.connect()
        await self.__build_message(
            "CHECK",
            '<Authentication id="{}" username="{}"/>'.format(
                self.session_id, self.username
            ),
        )

    def disconnect(self):
        """Disconnect from IT4WIFI."""
        self.connection = False
        self.command_id = 0
        self.command_sequence = 1
        self.serv_writer.close()
