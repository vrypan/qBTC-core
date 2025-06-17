#!/usr/bin/env python3

import asyncio
import uvicorn
from web.web import app
from rpc.rpc import rpc_app
from node.startup import startup, shutdown
from log_utils import setup_logging

# Setup structured logging
logger = setup_logging(
    level="INFO",
    log_file="qbtc.log",
    enable_console=True,
    enable_structured=True
)

async def main():
    logger.info("Starting qBTC-core node")
    
    try:
        await startup()
        logger.info("Node startup completed successfully")
    except Exception as e:
        logger.error(f"Failed to start node: {str(e)}")
        raise

    config_web = uvicorn.Config(
        app,
        host="0.0.0.0",
        port=8080,
        log_level="info",
        access_log=True
    )
    server_web = uvicorn.Server(config_web)
    logger.info("Web server configured on port 8080")

    config_rpc = uvicorn.Config(
        rpc_app,
        host="0.0.0.0",
        port=8332,
        log_level="info",
        access_log=True
    )
    server_rpc = uvicorn.Server(config_rpc)
    logger.info("RPC server configured on port 8332")

    try:
        logger.info("Starting web and RPC servers")
        await asyncio.gather(server_web.serve(), server_rpc.serve())
    except asyncio.CancelledError:
        logger.info("Servers cancelled, shutting down gracefully")
    except Exception as e:
        logger.error(f"Server error: {str(e)}")
        raise
    finally:
        logger.info("Initiating shutdown")
        await shutdown()
        logger.info("Shutdown completed")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Received interrupt signal, shutting down")
    except Exception as e:
        logger.critical(f"Fatal error: {str(e)}")
        raise
