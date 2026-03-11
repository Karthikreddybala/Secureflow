#!/usr/bin/env python3
"""
Test script to verify WebSocket connections are working properly.
This script tests both the alert and network WebSocket endpoints.
"""

import asyncio
import websockets
import json
import time

async def test_websocket_connection(uri, connection_name):
    """Test a single WebSocket connection"""
    print(f"\n=== Testing {connection_name} WebSocket ===")
    print(f"Connecting to: {uri}")
    
    try:
        async with websockets.connect(uri) as websocket:
            print(f"✅ {connection_name} WebSocket connected successfully!")
            
            # Test sending a message
            test_message = {
                "test": True,
                "timestamp": time.time(),
                "message": f"Test message from {connection_name}"
            }
            
            await websocket.send(json.dumps(test_message))
            print(f"✅ Sent test message to {connection_name}")
            
            # Wait for any response (with timeout)
            try:
                response = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                print(f"✅ Received response from {connection_name}: {response[:100]}...")
            except asyncio.TimeoutError:
                print(f"ℹ️  No response received from {connection_name} (this is normal if no server is broadcasting)")
            
            return True
            
    except Exception as e:
        print(f"❌ {connection_name} WebSocket failed: {e}")
        return False

async def main():
    """Test both WebSocket connections"""
    print("WebSocket Connection Test")
    print("=" * 50)
    
    # Test URLs
    alert_url = "ws://localhost:8000/ws/alerts/"
    network_url = "ws://localhost:8000/ws/network/"
    
    # Test connections
    alert_success = await test_websocket_connection(alert_url, "Alert")
    network_success = await test_websocket_connection(network_url, "Network")
    
    # Summary
    print("\n" + "=" * 50)
    print("TEST SUMMARY:")
    print(f"Alert WebSocket: {'✅ PASS' if alert_success else '❌ FAIL'}")
    print(f"Network WebSocket: {'✅ PASS' if network_success else '❌ FAIL'}")
    
    if alert_success and network_success:
        print("\n🎉 All WebSocket connections are working!")
    else:
        print("\n⚠️  Some WebSocket connections failed. Please check:")
        print("  - Django server is running")
        print("  - Daphne is properly installed and configured")
        print("  - Channels is properly configured")
        print("  - CORS settings are correct")

if __name__ == "__main__":
    asyncio.run(main())