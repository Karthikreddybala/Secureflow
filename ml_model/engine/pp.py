"""
SecureFlow — engine/pp.py
Dual-interface packet capture: laptop Wi-Fi + Windows Mobile Hotspot adapter.

Auto-detects:
  • Primary Wi-Fi  → interface with a real routable IP (192.168.x / 10.x / 172.x)
  • Hotspot adapter → MediaTek Wi-Fi card #2/#3/… OR any interface whose IP
                      is in the Windows hotspot subnet (192.168.137.x / 169.254.x
                      with no default-route IP on same adapter)

Both sniffers push into the same thread-safe queue → same WebSocket pipeline →
same Django ML engine.  No changes needed in views.py.
"""

import asyncio
import json
import logging
import queue
import re
import subprocess
import sys
import threading
import time

import websockets
from scapy.all import IP, TCP, UDP, PcapReader, sniff

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ── WebSocket endpoint ─────────────────────────────────────────────────────────
WS_SERVER = "ws://127.0.0.1:8000/ws/packets/"

# ── Batch settings ─────────────────────────────────────────────────────────────
PACKET_BATCH_SIZE = 100
PACKET_BATCH_TIME = 0.5   # seconds

# ── Globals ────────────────────────────────────────────────────────────────────
packet_batch: list  = []
last_send           = time.time()
packet_queue        = queue.Queue(maxsize=5000)

# ── Interface auto-detection ───────────────────────────────────────────────────
# Subnets that indicate a REAL internet-facing adapter
_ROUTABLE_RE = re.compile(
    r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.(?!137\.))"
)
# Windows Mobile Hotspot default subnet
_HOTSPOT_RE = re.compile(r"^192\.168\.137\.")


def _get_all_ifaces() -> list[dict]:
    """Return Scapy's Windows interface list (graceful fallback)."""
    try:
        from scapy.arch.windows import get_windows_if_list
        return get_windows_if_list()
    except Exception as exc:
        logger.warning("Cannot enumerate interfaces via Scapy: %s", exc)
        return []


def _detect_interfaces() -> tuple[str | None, str | None]:
    """
    Returns (wifi_iface, hotspot_iface) — either may be None.

    Strategy
    --------
    1. Walk all interfaces that have at least one assigned IP.
    2. Primary Wi-Fi  = first interface whose IPs include a routable private
                        address AND whose description contains "Wi-Fi 7" /
                        "Wireless" (prefers the laptop's own connection).
    3. Hotspot        = interface whose description marks it as virtual card #2
                        (Windows always creates a numbered clone for hotspot).
                        Fall back to 192.168.137.x subnet detection.
    """
    ifaces = _get_all_ifaces()

    wifi_iface    : str | None = None
    hotspot_iface : str | None = None

    # ── Pass 1: find the primary (routable) Wi-Fi adapter ─────────────────────
    for iface in ifaces:
        name = iface.get("name", "")
        desc = iface.get("description", "").lower()
        ips  = iface.get("ips", [])

        # Skip filter-driver clones (they have '-' in the name after base name)
        if re.search(r"-(WFP|Npcap|QoS|Native|Virtual)", name):
            continue

        has_routable = any(_ROUTABLE_RE.match(ip) for ip in ips)

        if has_routable and ("wi-fi" in desc or "wireless" in desc):
            # Prefer the one that looks like the base card (no #N suffix)
            if "#" not in desc:
                wifi_iface = name
                break           # exact match — stop searching
            elif wifi_iface is None:
                wifi_iface = name   # keep as fallback

    # ── Pass 2: find the hotspot / virtual adapter ─────────────────────────────
    for iface in ifaces:
        name = iface.get("name", "")
        desc = iface.get("description", "").lower()
        ips  = iface.get("ips", [])

        if re.search(r"-(WFP|Npcap|QoS|Native|Virtual)", name):
            continue
        if name == wifi_iface:
            continue

        # Condition A: MediaTek virtual card with a numeric suffix (#2, #3 …)
        is_virtual_card = bool(
            re.search(r"wi-fi 7.*#\d+|wireless lan card #\d+", desc)
        )
        # Condition B: IP in the hotspot subnet
        has_hotspot_ip = any(_HOTSPOT_RE.match(ip) for ip in ips)
        # Condition C: "wi-fi direct" or "hosted network" in description
        is_hotspot_desc = any(
            kw in desc for kw in ("wi-fi direct", "hosted network", "microsoft wifi direct")
        )

        if has_hotspot_ip or is_hotspot_desc or (
            is_virtual_card and name != wifi_iface
        ):
            hotspot_iface = name
            break

    return wifi_iface, hotspot_iface


# ── PacketProcessor ────────────────────────────────────────────────────────────
class PacketProcessor:
    def __init__(self):
        self.ws_connection   = None
        self.ws_lock         = asyncio.Lock()
        self.shutdown_event  = asyncio.Event()
        self.reconnect_attempts      = 0
        self.max_reconnect_attempts  = None
        self.heartbeat_interval      = 10
        self.connection_state        = "disconnected"
        self.last_connection_attempt = 0.0
        self.min_reconnect_delay     = 1
        self.max_reconnect_delay     = 15
        self.main_event_loop         = None
        self.packet_processing_enabled = True

    # ── WebSocket helpers ──────────────────────────────────────────────────────
    async def connect_ws(self):
        current_attempt = 0
        self.connection_state = "connecting"

        while not self.shutdown_event.is_set():
            current_attempt += 1
            try:
                self.last_connection_attempt = time.time()
                logger.info("Connecting to %s (attempt %d)", WS_SERVER, current_attempt)
                self.ws_connection = await websockets.connect(
                    WS_SERVER,
                    ping_interval=20,
                    ping_timeout=20,
                    close_timeout=10,
                )
                logger.info("Connected to WebSocket server")
                self.connection_state    = "connected"
                self.reconnect_attempts  = 0
                return True
            except Exception as exc:
                self.reconnect_attempts += 1
                wait = min(
                    self.min_reconnect_delay * (2 ** min(current_attempt - 1, 5)),
                    self.max_reconnect_delay,
                )
                logger.error("WS connect failed (attempt %d): %s", current_attempt, exc)
                logger.info("Retrying in %.1f s …", wait)
                await asyncio.sleep(wait)

        self.connection_state = "disconnected"
        return False

    async def disconnect_ws(self):
        if self.ws_connection:
            try:
                await self.ws_connection.close()
                logger.info("WebSocket closed")
            except Exception as exc:
                logger.error("WS close error: %s", exc)
            finally:
                self.ws_connection = None

    async def send_packet_batch(self):
        global packet_batch
        if not packet_batch:
            return

        async with self.ws_lock:
            if self.connection_state != "connected" or not self.ws_connection:
                logger.warning("WS not connected (%s), reconnecting …", self.connection_state)
                if not await self.connect_ws():
                    logger.error("Reconnect failed — keeping batch for retry")
                    return

            try:
                loop = asyncio.get_running_loop()
                if not loop or not loop.is_running():
                    logger.error("Event loop gone — cannot send packets")
                    self.ws_connection    = None
                    self.connection_state = "disconnected"
                    return

                await self.ws_connection.send(json.dumps({"packets": packet_batch}))
                logger.debug("Sent batch: %d packets", len(packet_batch))
                packet_batch = []

            except websockets.exceptions.ConnectionClosed as exc:
                logger.error("WS connection closed: %s", exc)
                self.ws_connection    = None
                self.connection_state = "disconnected"
            except RuntimeError as exc:
                if "Event loop is closed" in str(exc):
                    logger.critical("Event loop closed — shutting down processor")
                    self.packet_processing_enabled = False
                    self.shutdown_event.set()
                else:
                    logger.error("RuntimeError in send_packet_batch: %s", exc)
                    self.ws_connection    = None
                    self.connection_state = "disconnected"
            except Exception as exc:
                logger.error("WS send error: %s", exc)
                self.ws_connection    = None
                self.connection_state = "disconnected"

    async def heartbeat(self):
        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(self.heartbeat_interval)
                if self.ws_connection:
                    await self.ws_connection.ping()
                    logger.debug("WS heartbeat sent")
            except websockets.exceptions.ConnectionClosed:
                logger.warning("Heartbeat failed: connection closed")
                self.ws_connection    = None
                self.connection_state = "disconnected"
            except Exception as exc:
                logger.error("Heartbeat error: %s", exc)
                self.connection_state = "disconnected"

    def get_connection_status(self) -> dict:
        return {
            "state":              self.connection_state,
            "reconnect_attempts": self.reconnect_attempts,
            "has_connection":     self.ws_connection is not None,
            "batch_size":         len(packet_batch),
        }

    # ── Packet extraction ──────────────────────────────────────────────────────
    def add_packet(self, pkt, source_iface: str = ""):
        """Extract rich fields from a Scapy packet and append to the batch."""
        global packet_batch
        try:
            has_ip    = IP in pkt
            src       = pkt[IP].src   if has_ip else "unknown"
            dst       = pkt[IP].dst   if has_ip else "unknown"
            proto     = pkt[IP].proto if has_ip else 0
            ip_hdr    = pkt[IP].ihl * 4 if has_ip else 0

            sport     = int(pkt.sport) if hasattr(pkt, "sport") else 0
            dport     = int(pkt.dport) if hasattr(pkt, "dport") else 0

            has_tcp   = TCP in pkt
            tcp_flags = int(pkt[TCP].flags)   if has_tcp else 0
            tcp_hdr   = pkt[TCP].dataofs * 4  if has_tcp else 0

            packet_info = {
                "timestamp":    time.time(),
                "src":          src,
                "dst":          dst,
                "sport":        sport,
                "dport":        dport,
                "proto":        proto,
                "size":         len(pkt),
                "ip_hdr_len":   ip_hdr,
                "tcp_hdr_len":  tcp_hdr,
                "flags":        tcp_flags,
                "source_iface": source_iface,   # tag: "wifi" | "hotspot"
            }
            packet_batch.append(packet_info)
        except Exception as exc:
            logger.error("Packet extraction error: %s", exc)

    async def process_packet(self, pkt, source_iface: str = ""):
        global last_send
        self.add_packet(pkt, source_iface)
        now = time.time()
        if len(packet_batch) >= PACKET_BATCH_SIZE or now - last_send > PACKET_BATCH_TIME:
            await self.send_packet_batch()
            last_send = now

    def packet_callback(self, pkt, source_iface: str = ""):
        """Scapy callback — thread-safe: routes into the async queue."""
        if self.shutdown_event.is_set():
            return
        try:
            packet_queue.put_nowait((pkt, source_iface))
        except queue.Full:
            logger.warning("Packet queue full — dropping packet from %s", source_iface)
        except Exception as exc:
            logger.error("queue.put error: %s", exc)

    async def process_packets_from_queue(self):
        """Drain the shared queue in the async event loop."""
        while not self.shutdown_event.is_set():
            try:
                pkt, source_iface = await asyncio.to_thread(packet_queue.get, True, 1.0)
                await self.process_packet(pkt, source_iface)
                packet_queue.task_done()
            except queue.Empty:
                continue
            except Exception as exc:
                logger.error("Queue processing error: %s", exc)

    # ── Sniffer threads ────────────────────────────────────────────────────────
    def _run_sniff(self, interface: str, label: str):
        """Run a blocking Scapy sniff in a thread-pool executor thread."""
        logger.info("🔍 Sniffer started  →  %s  (%s)", interface, label)
        try:
            sniff(
                iface=interface,
                store=False,
                prn=lambda pkt: self.packet_callback(pkt, label),
                stop_filter=lambda _: self.shutdown_event.is_set(),
            )
        except Exception as exc:
            logger.error("Sniffer error on %s (%s): %s", interface, label, exc)
        finally:
            logger.info("🛑 Sniffer stopped  →  %s  (%s)", interface, label)

    async def start_multi_capture(self, interfaces: list[tuple[str, str]]):
        """
        Start one sniffer thread per (interface_name, label) pair.
        All sniffers share the same packet_queue.

        Parameters
        ----------
        interfaces : list of (name, label)
            e.g. [("Wi-Fi", "wifi"), ("Wi-Fi 2", "hotspot")]
        """
        self.main_event_loop = asyncio.get_running_loop()

        heartbeat_task = asyncio.create_task(self.heartbeat())
        queue_task     = asyncio.create_task(self.process_packets_from_queue())

        loop = asyncio.get_event_loop()

        # Launch one sniffer per interface (each in its own executor thread)
        sniffer_tasks = [
            loop.run_in_executor(None, self._run_sniff, name, label)
            for name, label in interfaces
        ]

        try:
            # Wait for all sniffers (they run until shutdown_event is set)
            await asyncio.gather(*sniffer_tasks)
        except KeyboardInterrupt:
            logger.info("Capture interrupted by user")
        except Exception as exc:
            logger.error("Capture error: %s", exc)
        finally:
            heartbeat_task.cancel()
            queue_task.cancel()
            try:
                await heartbeat_task
                await queue_task
            except asyncio.CancelledError:
                pass

    # ── PCAP replay ────────────────────────────────────────────────────────────
    async def replay_pcap(self, pcap_file: str):
        logger.info("▶  PCAP replay: %s", pcap_file)
        prev_time    = None
        packet_count = 0
        try:
            for pkt in PcapReader(pcap_file):
                if self.shutdown_event.is_set():
                    break
                if prev_time is not None:
                    delay = float(pkt.time) - prev_time
                    if delay > 0:
                        await asyncio.sleep(min(delay, 0.05))
                prev_time = float(pkt.time)
                packet_count += 1
                try:
                    packet_queue.put_nowait((pkt, "pcap"))
                except queue.Full:
                    logger.warning("Queue full during PCAP replay — dropping")
            logger.info("PCAP replay complete. Packets: %d", packet_count)
        except Exception as exc:
            logger.error("PCAP replay error: %s", exc)

    # ── Shutdown ───────────────────────────────────────────────────────────────
    async def shutdown(self):
        logger.info("Shutting down …")
        self.shutdown_event.set()
        await self.disconnect_ws()


# ── Main ───────────────────────────────────────────────────────────────────────
async def main():
    processor = PacketProcessor()

    # ── Connect WebSocket first ────────────────────────────────────────────────
    if not await processor.connect_ws():
        logger.error("Cannot connect to Django WebSocket — is the server running?")
        return

    # Start the queue-to-WS pipeline even during PCAP replay
    asyncio.create_task(processor.process_packets_from_queue())

    # ── PCAP replay mode ───────────────────────────────────────────────────────
    if len(sys.argv) > 1:
        logger.info("PCAP mode — replaying: %s", sys.argv[1])
        await processor.replay_pcap(sys.argv[1])
        await processor.shutdown()
        return

    # ── Live capture mode ──────────────────────────────────────────────────────
    wifi_iface, hotspot_iface = _detect_interfaces()

    # Build interface list
    interfaces: list[tuple[str, str]] = []

    if wifi_iface:
        interfaces.append((wifi_iface, "wifi"))
        logger.info("✓  Primary Wi-Fi interface   → %s", wifi_iface)
    else:
        # Hard fallback
        logger.warning("Could not auto-detect Wi-Fi interface — falling back to 'Wi-Fi'")
        interfaces.append(("Wi-Fi", "wifi"))

    if hotspot_iface:
        interfaces.append((hotspot_iface, "hotspot"))
        logger.info("✓  Hotspot interface         → %s", hotspot_iface)
    else:
        logger.warning(
            "Hotspot adapter NOT detected — capturing laptop traffic only.\n"
            "  Enable Mobile Hotspot (Settings → Network & Internet → Mobile Hotspot)\n"
            "  then restart pp.py to also monitor hotspot clients."
        )

    if not interfaces:
        logger.error("No usable interfaces found — exiting.")
        await processor.shutdown()
        return

    logger.info("=" * 60)
    logger.info("SecureFlow dual-capture starting on %d interface(s):", len(interfaces))
    for name, label in interfaces:
        logger.info("  [%s]  %s", label.upper().ljust(7), name)
    logger.info("=" * 60)

    try:
        await processor.start_multi_capture(interfaces)
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
    except Exception as exc:
        logger.error("Fatal capture error: %s", exc)
    finally:
        await processor.shutdown()


if __name__ == "__main__":
    logger.info("SecureFlow packet sensor v2.0 (dual-capture) starting …")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Packet sensor stopped by user")
    except Exception as exc:
        logger.error("Fatal error: %s", exc)
