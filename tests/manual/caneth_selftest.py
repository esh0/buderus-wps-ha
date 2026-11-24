import socket, sys, threading, time, logging
# Append, don't prepend: the integration dir contains select.py, which would
# shadow the stdlib 'select' module (imported by socket/asyncio).
sys.path.append(sys.argv[1])
from buderus_wps.can_adapter import USBtinAdapter
from buderus_wps.can_message import CANMessage
from buderus_wps.transport_caneth import binary_to_slcan, slcan_to_binary
from buderus_wps.exceptions import DeviceCommunicationError, DeviceDisconnectedError

# --- codec round trip
for line in ["T01FD7FE0412345678", "R01FDBFE00", "T0C0840022011A", "t1232AABB", "r1230"]:
    b = slcan_to_binary(line); assert len(b) == 13
    assert binary_to_slcan(b).decode().rstrip("\r") == line[0] + line[1:].upper(), (line, binary_to_slcan(b))
print("codec ok")

def frame(cid, data=b"", rtr=False):
    return bytes([0x80 | (0x40 if rtr else 0) | len(data)]) + cid.to_bytes(4,"big") + data.ljust(8,b"\0")

received = []
state = {"conn": None}
def server(srv):
    while True:
        c, _ = srv.accept(); state["conn"] = c
        def bcast():  # broadcast noise, 3 frames per TCP segment
            try:
                while True:
                    c.sendall(frame(0x0C084060, b"\x00\xe1")*3); time.sleep(0.005)
            except OSError: pass
        threading.Thread(target=bcast, daemon=True).start()
        buf = b""
        try:
            while True:
                d = c.recv(4096)
                if not d: break
                buf += d
                while len(buf) >= 13:
                    f, buf = buf[:13], buf[13:]; received.append(f)
                    cid = int.from_bytes(f[1:5],"big")
                    if f[0] & 0x40 and cid == 0x01FD7FE0:   # element count request
                        c.sendall(frame(0x09FD7FE0, b"\x00\x00\x07\xd0"))
                    if f[0] & 0x40 and cid == 0x01FDBFE0:   # bulk stream request
                        c.sendall(b"".join(frame(0x09FDBFE0, bytes([i]*8)) for i in range(50)))
        except OSError: pass

srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
srv.bind(("127.0.0.1",0)); srv.listen(); port = srv.getsockname()[1]
threading.Thread(target=server, args=(srv,), daemon=True).start()

a = USBtinAdapter(f"caneth://127.0.0.1:{port}", timeout=2.0)
a.connect(); assert a.is_open; print("connect/init ok")
time.sleep(0.3)  # let broadcasts pile up
# request -> response; must not return a broadcast that arrived before the request
a.flush_input_buffer()
a.send_frame_nowait(CANMessage(0x01FD7FE0, b"", is_extended_id=True, is_remote_frame=True))
t0=time.time(); got=None
while time.time()-t0 < 2:
    m = a._read_frame(timeout=1)
    if m and m.arbitration_id == 0x09FD7FE0: got = m; break
assert got and got.data == b"\x00\x00\x07\xd0", got; print("rtr round-trip ok", got.data.hex())
assert any(f[0]==0xC0 and int.from_bytes(f[1:5],'big')==0x01FD7FE0 for f in received), "RTR flag not sent"
# no frame loss under batching: count broadcasts in a window
a.flush_input_buffer(); n=0; t0=time.time()
while time.time()-t0 < 0.5:
    if a._read_frame(timeout=0.2): n += 1
print("frames read in 0.5s:", n)
a.flush_input_buffer()
a.send_frame_nowait(CANMessage(0x01FDBFE0, b"", is_extended_id=True, is_remote_frame=True))
data = a.receive_stream(400, timeout=3, frame_filter=0x09FDBFE0)
assert data == b"".join(bytes([i]*8) for i in range(50)), len(data); print("receive_stream ok", len(data))
# link loss -> DeviceDisconnectedError / DeviceCommunicationError
state["conn"].shutdown(socket.SHUT_RDWR); state["conn"].close(); time.sleep(0.3)
try:
    a._read_frame(timeout=1); print("FAIL no error")
except (DeviceCommunicationError, DeviceDisconnectedError) as e:
    print("link loss surfaced:", type(e).__name__)
a.disconnect(); assert not a.is_open
a.connect(); print("reconnect ok"); a.disconnect()
# bad host
try:
    USBtinAdapter("caneth://127.0.0.1:1").connect()
except Exception as e: print("unreachable ->", type(e).__name__)
