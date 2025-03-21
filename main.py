import sys
import os
import signal
from nexus_nids import AdvancedNexusNIDS
from nexus_api import NexusAPI

def signal_handler(sig, frame):
    """Handles Ctrl+C signal"""
    print("\nShutting down Nexus NIDS...")
    sys.exit(0)

def main():
    """Main function"""
    # Register signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    
    # Check if running as root
    if os.geteuid() != 0:
        print("Error: This program must be run as root!")
        sys.exit(1)
    
    # Initialize NIDS
    nids = AdvancedNexusNIDS()
    
    # Initialize API with reference to NIDS instance
    api = NexusAPI(nids)
    api.start_api()  # Start the API server in a separate thread
    
    # Start the NIDS
    nids.start_sniffing()

if __name__ == "__main__":
    main()
