from django.shortcuts import render
import json
import joblib
import pandas as pd
import requests
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync, sync_to_async
import sys
import subprocess
import os
import time
import numpy as np
import asyncio
import logging

# Set up logging
logger = logging.getLogger(__name__)

# Create a task queue for background processing
processing_queue = asyncio.Queue()


flows = {}

# Flow processing configuration
FLOW_TIMEOUT = 15  # Increased from 3 to 15 seconds for better data accumulation
MIN_PACKETS_FOR_PROCESSING = 5  # Minimum packets required before processing a flow
MAX_FLOW_SIZE = 1000  # Maximum packets per flow before forced processing

# Load ML models
rf = joblib.load("C:\\Users\\saket\\3-2Mini\\secureflow\\ml_model\\ai_models\\models\\rf.plk")
iso = joblib.load("C:\\Users\\saket\\3-2Mini\\secureflow\\ml_model\\ai_models\\models\\isolation_forest.pkl")
FEATURES = [" Flow Duration", " Total Fwd Packets", " Total Backward Packets", "Total Length of Fwd Packets", " Total Length of Bwd Packets", " Fwd Packet Length Mean", " Bwd Packet Length Mean", "Flow Bytes/s", " Flow Packets/s", " Flow IAT Mean", " Flow IAT Std", "Fwd IAT Total", " Fwd IAT Mean", " Fwd IAT Std", "Bwd IAT Total", " Bwd IAT Mean", " Bwd IAT Std", "Fwd PSH Flags", " Bwd PSH Flags", " Fwd URG Flags", " Bwd URG Flags", " Fwd Header Length", " Bwd Header Length", "Fwd Packets/s", " Bwd Packets/s", " Packet Length Mean", " Packet Length Std", " Packet Length Variance", "FIN Flag Count", " SYN Flag Count", " RST Flag Count", " PSH Flag Count", " ACK Flag Count", " Average Packet Size", " Avg Fwd Segment Size", " Avg Bwd Segment Size", " Fwd Header Length.1", " act_data_pkt_fwd", " min_seg_size_forward", "Active Mean", " Active Std", " Active Max", " Active Min", "Idle Mean", " Idle Std", " Idle Max", " Idle Min"]  # 46 ordered feature list

# Performance monitoring
processing_stats = {
    "flows_processed": 0,
    "packets_processed": 0,
    "avg_processing_time": 0.0,
    "queue_depth": 0,
    "start_time": time.time()
}




def fusion_engine(rf_label, rf_conf, iso_score):
    """
    Combines RandomForest + IsolationForest signals to produce:
    - final_score
    - severity
    - attack_type
    
    Now sends alerts for ALL flows (including normal ones) to dashboard.
    """
    # If RF predicts attack → trust RF
    if rf_label != "Normal":
        severity = "High" if rf_conf > 0.80 else "Medium"
        return {
            "final_score": round(float(rf_conf * 100), 2),
            "attack_type": rf_label,
            "severity": severity
        }

    # Otherwise, trust Isolation Forest
    if iso_score > 0.3:
        return {
            "final_score": iso_score,
            "attack_type": "Anomaly",
            "severity": "Medium"
        }

    # Send alert for normal flows too (changed from returning None)
    return {
        "final_score": iso_score,
        "attack_type": "Normal",
        "severity": "Low"
    }

def flow_id(pkt):

    return (
        pkt["src"],
        pkt["dst"],
        pkt["sport"],
        pkt["dport"],
        pkt["proto"]
    )


def process_packet(pkt):
    fid = flow_id(pkt)
    if not fid:
        return
    
    now = time.time()
    size = len(pkt)

    if fid not in flows:
        flows[fid] = {
            "timestamps": [],
            "sizes": [],
            "fwd_sizes": [],
            "bwd_sizes": [],
            "flags": [],
            "fwd_hdr_len": [],
            "bwd_hdr_len": [],
            "src": fid[0],
            "last": now
        }

    f = flows[fid]
    direction = "fwd" if pkt["src"] == f["src"] else "bwd"

    # GENERAL
    f["timestamps"].append(now)
    f["sizes"].append(size)

    # LENGTHS
    if direction == "fwd":
        f["fwd_sizes"].append(size)
    else:
        f["bwd_sizes"].append(size)

    # FLAGS
    # if pkt.haslayer("TCP"):
    #     flags = pkt.sprintf("%TCP.flags%")
    #     for fl in flags:
    #         f["flags"].append(fl)

    # # HEADER LENGTHS
    # if pkt.haslayer("IP"):
    #     hlen = pkt["IP"].ihl * 4
    #     if direction == "fwd":
    #         f["fwd_hdr_len"].append(hlen)
    #     else:
    #         f["bwd_hdr_len"].append(hlen)

    # f["last"] = now


def compute_features(f):
    t = f["timestamps"]
    dur = (t[-1] - t[0]) if len(t) > 1 else 0.001
    sizes = f["sizes"]
    iats = np.diff(t) if len(t) > 1 else [0]

    fwd = f["fwd_sizes"]
    bwd = f["bwd_sizes"]

    # Prevent division by zero
    dur_safe = max(dur, 0.001)
    total_packets = len(sizes)
    total_packets_safe = max(total_packets, 1)

    return {
        # Duration + basic counts
        "Flow Duration": dur,
        "Total Fwd Packets": len(fwd),
        "Total Backward Packets": len(bwd),
        "Total Length of Fwd Packets": sum(fwd),
        "Total Length of Bwd Packets": sum(bwd),
        "Fwd Packet Length Mean": np.mean(fwd) if fwd else 0,
        "Bwd Packet Length Mean": np.mean(bwd) if bwd else 0,

        # Rates - use safe duration to prevent division by zero
        "Flow Bytes/s": sum(sizes) / dur_safe,
        "Flow Packets/s": total_packets / dur_safe,

        # IAT
        "Flow IAT Mean": np.mean(iats) if len(iats) > 0 else 0,
        "Flow IAT Std": np.std(iats) if len(iats) > 0 else 0,
        "Fwd IAT Total": sum(iats[:len(fwd)]) if len(fwd) > 0 else 0,
        "Fwd IAT Mean": np.mean(iats[:len(fwd)]) if len(fwd) > 0 else 0,
        "Fwd IAT Std": np.std(iats[:len(fwd)]) if len(fwd) > 0 else 0,
        "Bwd IAT Total": sum(iats[len(fwd):]) if len(bwd) > 0 else 0,
        "Bwd IAT Mean": np.mean(iats[len(fwd):]) if len(bwd) > 0 else 0,
        "Bwd IAT Std": np.std(iats[len(fwd):]) if len(bwd) > 0 else 0,

        # Flags
        "Fwd PSH Flags": f["flags"].count("P"),
        "Bwd PSH Flags": f["flags"].count("p"),
        "Fwd URG Flags": f["flags"].count("U"),
        "Bwd URG Flags": f["flags"].count("u"),

        # Header lengths
        "Fwd Header Length": np.mean(f["fwd_hdr_len"]) if f["fwd_hdr_len"] else 0,
        "Bwd Header Length": np.mean(f["bwd_hdr_len"]) if f["bwd_hdr_len"] else 0,

        # Packet rates per direction - use safe duration
        "Fwd Packets/s": len(fwd) / dur_safe,
        "Bwd Packets/s": len(bwd) / dur_safe,

        # Packet statistics
        "Packet Length Mean": np.mean(sizes) if sizes else 0,
        "Packet Length Std": np.std(sizes) if sizes else 0,
        "Packet Length Variance": np.var(sizes) if sizes else 0,

        # TCP flag counts
        "FIN Flag Count": f["flags"].count("F"),
        "SYN Flag Count": f["flags"].count("S"),
        "RST Flag Count": f["flags"].count("R"),
        "PSH Flag Count": f["flags"].count("P"),
        "ACK Flag Count": f["flags"].count("A"),

        # Additional flow-level features
        "Average Packet Size": sum(sizes) / total_packets_safe,
        "Avg Fwd Segment Size": np.mean(fwd) if fwd else 0,
        "Avg Bwd Segment Size": np.mean(bwd) if bwd else 0,

        "Fwd Header Length.1": np.mean(f["fwd_hdr_len"]) if f["fwd_hdr_len"] else 0,
        "act_data_pkt_fwd": len([x for x in fwd if x > 0]),
        "min_seg_size_forward": min(fwd) if fwd else 0,

        # Active/Idle
        "Active Mean": dur_safe / total_packets_safe,
        "Active Std": np.std(iats) if len(iats) > 0 else 0,
        "Active Max": max(iats) if len(iats) > 0 else 0,
        "Active Min": min(iats) if len(iats) > 0 else 0,

        "Idle Mean": np.mean(iats) if len(iats) > 0 else 0,
        "Idle Std": np.std(iats) if len(iats) > 0 else 0,
        "Idle Max": max(iats) if len(iats) > 0 else 0,
        "Idle Min": min(iats) if len(iats) > 0 else 0
    }


async def process_flow_features_async(features, flow_id=None):
    """
    Async version of process_flow_features to run in background.
    Now includes proper source and destination information from flow data.
    """
    try:
        df = pd.DataFrame([features], columns=FEATURES)
        logger.info("Processing flow features for prediction")
        
        # RF PREDICTION
        rf_pred_raw = rf.predict(df)[0]             
        rf_label = str(rf_pred_raw)
        rf_prob = float(rf.predict_proba(df)[0].max())

        # ISO FOREST SCORE
        iso_score = abs(float(iso.decision_function(df)[0]))

        fused = fusion_engine(rf_label, rf_prob, iso_score)

        # Extract source and destination from flow_id if available
        src_ip = "Unknown"
        dst_ip = "Unknown"
        protocol = "TCP"
        sport = ""
        dport = ""
        
        if flow_id and len(flow_id) >= 5:
            src_ip = flow_id[0]  # Source IP
            dst_ip = flow_id[1]  # Destination IP
            sport = str(flow_id[2])   # Source port (convert to string)
            dport = str(flow_id[3])   # Destination port (convert to string)
            protocol = str(flow_id[4])  # Protocol (convert to string)

        # Create simplified alert structure for frontend with correct src/dst
        alert_data = {
            "final": fused,
            "protocol": protocol,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "sport": sport,
            "dport": dport,
            "timestamp": time.time(),
            "message": f"Flow processed: {fused['attack_type']} ({fused['severity']})"
        }
        
        await send_alert_async(alert_data)
        return alert_data
    except Exception as e:
        logger.error(f"Error processing flow features: {e}")
        return None


async def send_alert_async(alert):
    """
    Async version of send_alert to avoid blocking.
    """
    try:
        channel_layer = get_channel_layer()
        logger.info("Broadcasting alert to dashboard: %s", alert)
        await channel_layer.group_send(
            "alerts",
            {
                "type": "send_alert",
                "data": alert
            }
        )
    except Exception as e:
        logger.error(f"Error sending alert: {e}")


async def process_single_flow(item):
    """Process a single flow with error handling and timing"""
    start_time = time.time()
    try:
        # Handle both old format (features) and new format (features, flow_id)
        if isinstance(item, tuple) and len(item) == 2:
            features, flow_id = item
        else:
            features = item
            flow_id = None
            
        result = await process_flow_features_async(features, flow_id)
        processing_time = time.time() - start_time
        
        # Update stats
        global processing_stats
        processing_stats["avg_processing_time"] = (
            (processing_stats["avg_processing_time"] * (processing_stats["flows_processed"] - 1)) + processing_time
        ) / max(processing_stats["flows_processed"], 1)
        
        logger.info(f"Flow processed in {processing_time:.3f}s")
        return result
    except Exception as e:
        logger.error(f"Error processing single flow: {e}")
        return None

async def background_worker(worker_id):
    """Individual worker for parallel processing"""
    logger.info(f"Background worker {worker_id} started")
    while True:
        try:
            # Get the next item from the queue (this will block until an item is available)
            features = await processing_queue.get()
            
            # Process the features asynchronously
            await process_single_flow(features)
            
            # Mark the task as done
            processing_queue.task_done()
            
        except Exception as e:
            logger.error(f"Error in worker {worker_id}: {e}")
            # If there's an error, still mark the task as done to prevent queue buildup
            if not processing_queue.empty():
                processing_queue.task_done()

async def start_background_workers(num_workers=3):
    """Start multiple background workers for parallel processing"""
    logger.info(f"Starting {num_workers} background workers")
    workers = []
    for i in range(num_workers):
        worker = asyncio.create_task(background_worker(i + 1))
        workers.append(worker)
    
    # Wait for all workers (they run indefinitely)
    await asyncio.gather(*workers)

def start_parallel_processors(num_workers=3):
    """Start parallel processors in a separate thread"""
    try:
        asyncio.run(start_background_workers(num_workers))
    except Exception as e:
        logger.error(f"Error in parallel processors: {e}")


def flush_flows_async():
    """
    Enhanced flow processing with multiple triggers:
    1. Time-based expiration (FLOW_TIMEOUT)
    2. Size-based processing (MIN_PACKETS_FOR_PROCESSING)
    3. Maximum size enforcement (MAX_FLOW_SIZE)
    """
    global processing_stats
    now = time.time()
    processed_flows = []

    for fid, f in list(flows.items()):
        total_packets = len(f["sizes"])
        time_since_last = now - f["last"]
        
        should_process = False
        reason = ""
        immediate_alert = False
        
        # Check processing triggers
        if time_since_last > FLOW_TIMEOUT:
            should_process = True
            immediate_alert = True  # Timeout flows need immediate alerts
            reason = f"timeout ({time_since_last:.1f}s)"
        elif total_packets >= MAX_FLOW_SIZE:
            should_process = True
            immediate_alert = True  # Large flows need immediate alerts
            reason = f"max_size ({total_packets})"
        elif total_packets >= MIN_PACKETS_FOR_PROCESSING and time_since_last > 5:
            should_process = True
            immediate_alert = True  # Size-triggered flows need immediate alerts
            reason = f"min_packets ({total_packets})"
        
        if should_process:
            features = compute_features(f)
            if immediate_alert:
                # Process immediately for alert generation with flow_id
                try:
                    asyncio.run(process_flow_features_async(features, fid))
                    logger.info(f"IMMEDIATE processing flow {fid} due to {reason} - {total_packets} packets")
                except Exception as e:
                    logger.error(f"Error in immediate processing: {e}")
                    # Fallback to background processing
                    processing_queue.put_nowait((features, fid))
            else:
                # Queue for background processing with flow_id
                processing_queue.put_nowait((features, fid))
                logger.info(f"Background processing flow {fid} due to {reason} - {total_packets} packets")
            
            processed_flows.append(fid)

    # Remove processed flows
    for fid in processed_flows:
        del flows[fid]
        processing_stats["flows_processed"] += 1
        processing_stats["packets_processed"] += len(flows.get(fid, {}).get("sizes", []))

def get_processing_stats():
    """Return current processing statistics"""
    global processing_stats
    uptime = time.time() - processing_stats["start_time"]
    return {
        "flows_processed": processing_stats["flows_processed"],
        "packets_processed": processing_stats["packets_processed"],
        "avg_packets_per_flow": processing_stats["packets_processed"] / max(processing_stats["flows_processed"], 1),
        "queue_depth": processing_queue.qsize(),
        "uptime_seconds": uptime,
        "flows_in_memory": len(flows),
        "processing_rate_flows_per_sec": processing_stats["flows_processed"] / max(uptime, 1),
        "processing_rate_packets_per_sec": processing_stats["packets_processed"] / max(uptime, 1)
    }


def process_flow_features_sync(features):
    """
    Synchronous wrapper for backward compatibility.
    This will be used for immediate processing when needed.
    """
    return asyncio.run(process_flow_features_async(features))


def flush_flows():
    now = time.time()

    expired = []

    for fid,f in flows.items():

        if now - f["last"] > FLOW_TIMEOUT:

            features = compute_features(f)
            process_flow_features(features)
            expired.append(fid)

    for fid in expired:
        del flows[fid]


async def send_packet_batch_async(packets):

    print("Broadcasting batch of", len(packets), "packets to dashboard")

    channel_layer = get_channel_layer()

    await channel_layer.group_send(
        "network_traffic",
        {
            "type": "send_traffic",
            "data": packets
        }
    )

async def send_alert_async(alert):

    channel_layer = get_channel_layer()
    print("Broadcasting alert to dashboard:", alert)

def send_alert(alert):

    channel_layer = get_channel_layer()
    print("Broadcasting alert to dashboard:", alert)
    async_to_sync(channel_layer.group_send)(
        "alerts",
        {
            "type":"send_alert",
            "data":alert
        }
    )


@csrf_exempt
def predict_flow(request):
    """
    HTTP endpoint to receive packet batches and process them asynchronously.
    This endpoint now returns immediately to prevent timeouts.
    """
    try:
        data = json.loads(request.body)
        packets = data["packets"]
        
        logger.info(f"Received {len(packets)} packets for processing")
        
        # 1️⃣ broadcast packets to dashboard (synchronous but fast)
        asyncio.run(send_packet_batch_async(packets))
        
        # 2️⃣ update flow engine (synchronous but fast)
        for pkt in packets:
            process_packet(pkt)
        
        # 3️⃣ queue flow processing for background (non-blocking)
        flush_flows_async()
        
        # Return immediately to prevent timeout
        return JsonResponse({
            "status": "ok",
            "message": "Packets received and queued for processing",
            "packet_count": len(packets)
        })
        
    except Exception as e:
        logger.error(f"Error in predict_flow: {e}")
        return JsonResponse({
            "status": "error",
            "message": str(e)
        }, status=500)
