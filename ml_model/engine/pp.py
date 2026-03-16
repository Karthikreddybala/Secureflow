import asyncio
import websockets
import json
import time
import logging
import queue
from scapy.all import sniff, PcapReader
from scapy.all import IP, TCP, UDP
import sys


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

WS_SERVER = "ws://127.0.0.1:8000/ws/packets/"

PACKET_BATCH_SIZE = 100
PACKET_BATCH_TIME = 0.5  # seconds

# Global variables
packet_batch = []
last_send = time.time()
ws_connection = None
ws_lock = asyncio.Lock()
shutdown_event = asyncio.Event()

# Thread-safe packet queue for communication between threads
packet_queue = queue.Queue(maxsize=5000)
packet_processing_task = None

class PacketProcessor:
    def __init__(self):
        self.ws_connection = None
        self.ws_lock = asyncio.Lock()
        self.shutdown_event = asyncio.Event()
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = None
        self.heartbeat_interval = 10  # seconds
        self.connection_state = "disconnected"  # disconnected, connecting, connected, reconnecting
        self.last_connection_attempt = 0
        self.min_reconnect_delay = 1  # Minimum delay between reconnection attempts
        self.max_reconnect_delay = 15  # Maximum delay between reconnection attempts
        self.main_event_loop = None  # Store reference to main event loop
        self.packet_processing_enabled = True  # Control packet processing
        
    async def connect_ws(self):
        """Establish WebSocket connection with retry logic"""
        current_attempt = 0
        self.connection_state = "connecting"

        while not self.shutdown_event.is_set():
            current_attempt += 1
            try:
                self.last_connection_attempt = time.time()
                logger.info(f"Connecting to WebSocket server: {WS_SERVER} (attempt {current_attempt})")
                self.ws_connection = await websockets.connect(
                    WS_SERVER,
                    ping_interval=20,  # Send ping every 20 seconds
                    ping_timeout=20,   # Wait 20 seconds for pong
                    close_timeout=10   # Wait 10 seconds for close handshake
                )
                logger.info("Successfully connected to WebSocket server")
                self.connection_state = "connected"
                self.reconnect_attempts = 0  # Reset retry count on success
                return True
            except Exception as e:
                self.reconnect_attempts += 1
                wait_time = min(self.min_reconnect_delay * (2 ** min(current_attempt - 1, 5)), self.max_reconnect_delay)
                logger.error(f"WebSocket connection failed (attempt {current_attempt}): {e}")
                logger.info(f"Retrying connection in {wait_time} seconds...")
                await asyncio.sleep(wait_time)

        self.connection_state = "disconnected"
        return False

    async def disconnect_ws(self):
        """Safely disconnect WebSocket"""
        if self.ws_connection:
            try:
                await self.ws_connection.close()
                logger.info("WebSocket connection closed")
            except Exception as e:
                logger.error(f"Error closing WebSocket: {e}")
            finally:
                self.ws_connection = None

    async def send_packet_batch(self):
        """Send packet batch with error handling and reconnection"""
        global packet_batch
        
        if not packet_batch:
            return

        async with self.ws_lock:
            # Check connection state before attempting to send
            if self.connection_state != "connected" or not self.ws_connection:
                logger.warning(f"WebSocket not connected (state: {self.connection_state}), attempting to reconnect...")
                if not await self.connect_ws():
                    logger.error("Failed to reconnect, keeping packet batch for retry")
                    return

            try:
                # Validate event loop is still running before sending
                current_loop = asyncio.get_running_loop()
                if not current_loop or not current_loop.is_running():
                    logger.error("Event loop is not running, cannot send packets")
                    self.ws_connection = None
                    self.connection_state = "disconnected"
                    return

                await self.ws_connection.send(json.dumps({
                    "packets": packet_batch
                }))
                logger.debug(f"Sent batch: {len(packet_batch)} packets")
                packet_batch = []
            except websockets.exceptions.ConnectionClosed as e:
                logger.error(f"WebSocket connection closed: {e}")
                self.ws_connection = None
                self.connection_state = "disconnected"
                # Keep current batch intact; next cycle will reconnect and retry.
                return
            except RuntimeError as e:
                if "Event loop is closed" in str(e):
                    logger.critical("Event loop has been closed - this indicates a serious issue")
                    logger.critical("Shutting down packet processor to prevent further corruption")
                    self.packet_processing_enabled = False
                    self.shutdown_event.set()
                    return
                else:
                    logger.error(f"RuntimeError in send_packet_batch: {e}")
                    self.ws_connection = None
                    self.connection_state = "disconnected"
            except Exception as e:
                logger.error(f"WebSocket send error: {e}")
                self.ws_connection = None
                self.connection_state = "disconnected"

    async def heartbeat(self):
        """Send periodic heartbeat to keep connection alive"""
        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(self.heartbeat_interval)
                if self.ws_connection:
                    await self.ws_connection.ping()
                    logger.debug("Sent WebSocket heartbeat")
            except websockets.exceptions.ConnectionClosed:
                logger.warning("Heartbeat failed: connection closed")
                self.ws_connection = None
                self.connection_state = "disconnected"
            except Exception as e:
                logger.error(f"Heartbeat failed: {e}")
                self.connection_state = "disconnected"

    def get_connection_status(self):
        """Get current connection status for monitoring"""
        return {
            "state": self.connection_state,
            "reconnect_attempts": self.reconnect_attempts,
            "max_reconnect_attempts": self.max_reconnect_attempts,
            "last_connection_attempt": self.last_connection_attempt,
            "has_connection": self.ws_connection is not None,
            "batch_size": len(packet_batch)
        }

    def add_packet(self, pkt):
        """Extract rich packet fields from Scapy object and add to batch."""
        global packet_batch

        try:
            # ── IP layer ──────────────────────────────────────────────────────
            has_ip = IP in pkt
            src        = pkt[IP].src   if has_ip else "unknown"
            dst        = pkt[IP].dst   if has_ip else "unknown"
            proto      = pkt[IP].proto if has_ip else 0
            ip_hdr_len = pkt[IP].ihl * 4 if has_ip else 0   # bytes

            # ── Transport layer ───────────────────────────────────────────────
            sport = int(pkt.sport) if hasattr(pkt, 'sport') else 0
            dport = int(pkt.dport) if hasattr(pkt, 'dport') else 0

            # ── TCP-specific ──────────────────────────────────────────────────
            # Flag bits: FIN=0x01  SYN=0x02  RST=0x04  PSH=0x08  ACK=0x10  URG=0x20
            has_tcp    = TCP in pkt
            tcp_flags  = int(pkt[TCP].flags)      if has_tcp else 0
            tcp_hdr_len = pkt[TCP].dataofs * 4    if has_tcp else 0  # bytes

            packet_info = {
                "timestamp":   time.time(),
                "src":         src,
                "dst":         dst,
                "sport":       sport,
                "dport":       dport,
                "proto":       proto,
                "size":        len(pkt),
                "ip_hdr_len":  ip_hdr_len,    # for Fwd/Bwd Header Length
                "tcp_hdr_len": tcp_hdr_len,   # for Fwd/Bwd Header Length
                "flags":       tcp_flags,     # raw TCP flags bitmask
            }
            packet_batch.append(packet_info)
        except Exception as e:
            logger.error(f"Error processing packet: {e}")


    async def process_packet(self, pkt):
        """Process individual packet and manage batching"""
        global last_send
        
        self.add_packet(pkt)
        now = time.time()

        # Check if we should send batch (size or time threshold)
        should_send = (
            len(packet_batch) >= PACKET_BATCH_SIZE or 
            now - last_send > PACKET_BATCH_TIME
        )

        if should_send:
            await self.send_packet_batch()
            last_send = now

    def packet_callback(self, pkt):
        """Scapy callback function for packet capture - Thread-safe version"""
        # Add packet to queue for processing by main event loop
        if not self.shutdown_event.is_set():
            try:
                # Put packet in queue for main event loop to process
                packet_queue.put_nowait(pkt)
                logger.debug("Packet added to processing queue")
            except queue.Full:
                logger.warning("Packet queue is full, dropping packet")
            except Exception as e:
                logger.error(f"Error adding packet to queue: {e}")

    async def process_packets_from_queue(self):
        """Process packets from the queue in the main event loop"""
        while not self.shutdown_event.is_set():
            try:
                # Avoid blocking the async loop with Queue.get from a worker thread.
                pkt = await asyncio.to_thread(packet_queue.get, True, 1)
                
                # Process the packet
                await self.process_packet(pkt)
                
                # Mark task as done
                packet_queue.task_done()
                
            except queue.Empty:
                # No packets in queue, continue loop
                continue
            except Exception as e:
                logger.error(f"Error processing packet from queue: {e}")

    async def start_capture(self, interface="Wi-Fi"):
        """Start packet capture with graceful shutdown support"""
        logger.info(f"Starting packet capture on interface: {interface}")
        self.main_event_loop = asyncio.get_running_loop()
        
        # Start heartbeat task
        heartbeat_task = asyncio.create_task(self.heartbeat())
        
        # Start packet processing task
        packet_processing_task = asyncio.create_task(self.process_packets_from_queue())
        
        try:
            # Start packet capture in a separate thread
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._run_sniff, interface)
        except KeyboardInterrupt:
            logger.info("Packet capture interrupted by user")
        except Exception as e:
            logger.error(f"Error in packet capture: {e}")
        finally:
            # Cancel tasks
            heartbeat_task.cancel()
            packet_processing_task.cancel()
            
            try:
                await heartbeat_task
                await packet_processing_task
            except asyncio.CancelledError:
                pass

    def _run_sniff(self, interface):
        """Run scapy sniff in executor to avoid blocking"""
        try:
            sniff(
                iface=interface,
                store=False,
                prn=self.packet_callback,
                stop_filter=lambda x: self.shutdown_event.is_set()
            )
        except Exception as e:
            logger.error(f"Error in sniff thread: {e}")

    async def shutdown(self):
        """Graceful shutdown"""
        logger.info("Shutting down packet processor...")
        self.shutdown_event.set()
        await self.disconnect_ws()



    async def replay_pcap(self, pcap_file):
        """Replay packets from a PCAP file and feed them into the same processing pipeline"""
        
        logger.info(f"Starting PCAP replay: {pcap_file}")

        prev_time = None
        packet_count = 0

        try:
            for pkt in PcapReader(pcap_file):

                if self.shutdown_event.is_set():
                    break

                # simulate realistic timing
                if prev_time is not None:
                    delay = pkt.time - prev_time
                    if delay > 0:
                        await asyncio.sleep(min(delay, 0.05))

                prev_time = pkt.time
                packet_count += 1

                try:
                    packet_queue.put_nowait(pkt)
                except queue.Full:
                    logger.warning("Packet queue full during PCAP replay, dropping packet")

            logger.info(f"Finished PCAP replay. Packets processed: {packet_count}")

        except Exception as e:
            logger.error(f"Error during PCAP replay: {e}")


async def main():
    """Main function with proper error handling and shutdown"""
    processor = PacketProcessor()
    
    try:
        # Connect to WebSocket
        if not await processor.connect_ws():
            logger.error("Failed to connect to WebSocket server")
            return

        # Start queue processor
        asyncio.create_task(processor.process_packets_from_queue())

        # PCAP replay mode
        if len(sys.argv) > 1:
            print("Replaying packets from PCAP file:", sys.argv[1])
            pcap_file = sys.argv[1]
            await processor.replay_pcap(pcap_file)

        # Live capture mode
        else:
            await processor.start_capture("Wi-Fi")
        
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
    finally:
        await processor.shutdown()

# async def main():
#     """Main function with proper error handling and shutdown"""
#     processor = PacketProcessor()
    
#     try:
#         # Connect to WebSocket
#         if not await processor.connect_ws():
#             logger.error("Failed to connect to WebSocket server")
#             return

#         # Start packet capture
#         await processor.start_capture("Wi-Fi")
        
#     except KeyboardInterrupt:
#         logger.info("Received keyboard interrupt")
#     except Exception as e:
#         logger.error(f"Unexpected error: {e}")
#     finally:
#         await processor.shutdown()


if __name__ == "__main__":
    logger.info("Packet sensor started")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Packet sensor stopped by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
