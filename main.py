#!/usr/bin/env python3

import asyncio
import logging
import uvicorn
from web.web import app
from rpc.rpc import rpc_app
from node.startup import startup, shutdown

#logging.basicConfig(level=logging.ERROR, format="%(asctime)s - %(message)s")

async def main():
    await startup()

    config_web = uvicorn.Config(
        app,
        host="0.0.0.0",
        port=8080,
        log_level="error",
        ws="wsproto"
    )
    server_web = uvicorn.Server(config_web)

    config_rpc = uvicorn.Config(
        rpc_app,
        host="0.0.0.0",
        port=8332,
        log_level="error"
    )
    server_rpc = uvicorn.Server(config_rpc)

    try:
        await asyncio.gather(server_web.serve(), server_rpc.serve())
    except asyncio.CancelledError:
        pass
    finally:
        await shutdown()

if __name__ == "__main__":
    asyncio.run(main())
