import socket
import asyncio

async def http_banner(target, port):
    try:
        reader, writer = await asyncio.open_connection(target, port)
        writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
        await writer.drain()
        data = await reader.read(200)
        writer.close()
        return data.decode(errors="ignore")
    except:
        return ""

def grab_banner(target, port):
    try:
        with socket.socket() as s:
            s.settimeout(1)
            s.connect((target, port))
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            return s.recv(200).decode(errors="ignore")
    except:
        return ""
