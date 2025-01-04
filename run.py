"""
Hypercorn server configuration and management module for the Halberd Multi-Cloud Attack Tool.

This module provides server configuration and deployment capabilities for Halberd using Hypercorn ASGI server.
It supports both development and production deployments with configurable SSL, logging, and network settings.

Classes:
    Server: Main server configuration class that manages Hypercorn server settings and startup.

Functions:
    main(): Command-line interface for server configuration and startup.

Environment Variables:
    HALBERD_HOST: Host address to bind the server to (default: 127.0.0.1)
    HALBERD_PORT: Port number to run the server on (default: 8050)

Command Line Arguments:
    --host: Host address to bind to (overrides HALBERD_HOST)
    --port: Port to bind to (overrides HALBERD_PORT)
    --ssl-cert: Path to SSL certificate file for HTTPS
    --ssl-key: Path to SSL private key file for HTTPS
    --log-level: Server logging level (debug/info/warning/error/critical)
    --dev-server: Flag to use Flask development server instead of Hypercorn
    --dev-server-debug: Enable debug mode for development server

Example Usage:
    # Start production server
    python server.py

    # Start with custom host and port
    python server.py --host 0.0.0.0 --port 8443

    # Start with SSL
    python server.py --ssl-cert cert.pem --ssl-key key.pem

    # Start development server
    python server.py --dev-server

Notes:
    - The Server class validates SSL configurations and port numbers
    - Production deployments should use Hypercorn (default) instead of the development server
    - SSL certificate and key must be provided together for HTTPS
    - Log files are written to the configured server log file path
"""

from hypercorn.config import Config
from hypercorn.asyncio import serve
import asyncio
import argparse
import os
from core.Constants import SERVER_LOG_FILE
from halberd import app

class Server:
    """Halberd Server Configuration"""
    def __init__(self, host="127.0.0.1", port=8050, ssl_cert=None, ssl_key=None, log_level = "warning"):
        
        # Port number validation
        if not (0 <= port <= 65535):
            raise ValueError(f"Port number must be between 0 and 65535, got {port}")
        self.host = host
        self.port = port
        self.ssl_cert = ssl_cert
        self.ssl_key = ssl_key
        self.app = app.server
        self.log_level = log_level
            
    def _validate_ssl(self):
        """Validate SSL certificate and key if provided"""
        if bool(self.ssl_cert) != bool(self.ssl_key):
            raise ValueError("Both SSL certificate and key must be provided together")
        if self.ssl_cert and not os.path.exists(self.ssl_cert):
            raise ValueError(f"SSL certificate not found: {self.ssl_cert}")
        if self.ssl_key and not os.path.exists(self.ssl_key):
            raise ValueError(f"SSL key not found: {self.ssl_key}")
            
    def _get_hypercorn_config(self):
        """Generate Hypercorn configuration"""
        config = Config()
        config.bind = [f"{self.host}:{self.port}"]
        
        if self.ssl_cert and self.ssl_key:
            config.certfile = self.ssl_cert
            config.keyfile = self.ssl_key
        
        # Additional settings
        config.loglevel = self.log_level # Defaults to 'warning'
        config.accesslog = SERVER_LOG_FILE  # Log to server log file
        config.errorlog = SERVER_LOG_FILE   # Log to server log file
        config.worker_class = "asyncio"
        config.keep_alive_timeout = 65
        
        return config
        
    async def run(self):
        """Start Halberd server"""
        try:
            # SSL check
            self._validate_ssl()

            # Log server configuration
            protocol = "https" if self.ssl_cert else "http"
            print("Starting Halberd: Multi-Cloud Attack Tool server...")
            print(f"Server starting on {protocol}://{self.host}:{self.port}")
                
            # Start Hypercorn
            config = self._get_hypercorn_config()
            await serve(self.app, config)
            
        except Exception as e:
            raise RuntimeError(f"Server startup failed: {str(e)}")

def main():
    """Command line interface for the server with defaults and environment variable support"""
    parser = argparse.ArgumentParser(description="Halberd Multi-Cloud Attack Tool Server")
    parser.add_argument("--host", default=os.getenv("HALBERD_HOST", "127.0.0.1"), help="Host address to bind to")
    parser.add_argument("--port", type=int, default=int(os.getenv("HALBERD_PORT", "8050")), help="Port to bind to")
    parser.add_argument("--ssl-cert", help="Path to SSL certificate file")
    parser.add_argument("--ssl-key", help="Path to SSL key file")
    parser.add_argument("--log-level", choices= ["debug", "info", "warning", "error", "critical"], help="Server logging level")
    parser.add_argument("--dev-server", action="store_true", help="Flag launches Flask development server instead of Hypercorn")
    parser.add_argument("--dev-server-debug", action="store_true", help="Flag enables debug mode for development server")
    args = parser.parse_args()
    
    if args.dev_server:
        # Start development server
        app.run(
            host=args.host or "127.0.0.1", 
            port=args.port or "8050", 
            debug = args.dev_server_debug or False 
        ) 
    else:
        # Start production hypercorn server
        server = Server(
            host=args.host,
            port=args.port,
            ssl_cert=args.ssl_cert,
            ssl_key=args.ssl_key
        )

        asyncio.run(server.run()) # Run the async server

if __name__ == "__main__":
    main()