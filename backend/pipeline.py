"""
Week 2 (Member 2): Integration & Testing - Pipeline Integration
Connects raw HTTP byte parser with the API discovery and shadow endpoint detector.
"""

from parser import parse_raw_traffic
from discovery import APIDiscovery

def run_integration_pipeline():
    # Initialize the Discovery engine
    discovery = APIDiscovery()
    
    # Simulate incoming raw traffic packets from the eBPF/Rust sniffer
    sample_packets = [
        b"GET /api/v1/users/12345 HTTP/1.1\r\nHost: localhost\r\n\r\n",
        b"POST /api/v1/orders HTTP/1.1\r\nHost: localhost\r\n\r\n",
        b"GET /api/v2/secret-admin-panel HTTP/1.1\r\nHost: localhost\r\n\r\n" # Potential shadow API
    ]
    
    print("--- Starting API Sentinel Traffic Integration Pipeline ---")
    
    for raw_packet in sample_packets:
        # Step 1: Parse raw bytes into structured HTTP record
        record = parse_raw_traffic(raw_packet)
        
        if record.is_request and record.path:
            # Step 2: Normalize path and record into inventory discovery
            norm_path = discovery.record_endpoint(record.path)
            print(f"[+] Captured & Parsed: {record.method} {record.path} --> Normalized: {norm_path}")
            
    # Step 3: Check for Shadow / Zombie APIs against OpenAPI spec
    shadows = discovery.find_shadow_apis()
    print("\n--- Discovery Scan Complete ---")
    print(f"Flagged Shadow / Undocumented APIs: {shadows}")

if __name__ == "__main__":
    run_integration_pipeline()