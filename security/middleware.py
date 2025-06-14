"""
Security middleware for qBTC-core
"""

import time
import logging
from fastapi import Request
from .rate_limiter import rate_limiter, ddos_protection
from errors.exceptions import RateLimitError

logger = logging.getLogger(__name__)

async def security_middleware(request: Request, call_next):
    """Comprehensive security middleware"""
    client_ip = request.client.host if request.client else "unknown"
    start_time = time.time()
    
    try:
        # Track connection
        ddos_protection.track_connection(client_ip)
        
        # Check connection limits
        if not ddos_protection.check_connection_limit(client_ip):
            logger.warning(f"Connection limit exceeded for IP {client_ip}")
            raise RateLimitError("Too many concurrent connections")
        
        # Analyze request patterns for DDoS
        if not ddos_protection.analyze_request_pattern(request):
            logger.warning(f"Suspicious request pattern from IP {client_ip}")
            raise RateLimitError("Suspicious request pattern detected")
        
        # Apply rate limiting
        rate_limiter.check_rate_limit(request)
        
        # Process request
        response = await call_next(request)
        
        # Log successful request
        process_time = time.time() - start_time
        logger.info(
            "Request processed",
            extra={
                "method": request.method,
                "path": request.url.path,
                "client_ip": client_ip,
                "status_code": response.status_code,
                "process_time": process_time,
                "correlation_id": getattr(request.state, 'correlation_id', None)
            }
        )
        
        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        return response
        
    except RateLimitError:
        # Record failed request for pattern analysis
        rate_limiter.record_failed_request(client_ip, "rate_limit")
        raise
        
    except Exception as e:
        # Record failed request
        rate_limiter.record_failed_request(client_ip, "error")
        logger.error(f"Error processing request from {client_ip}: {str(e)}")
        raise
        
    finally:
        # Release connection
        ddos_protection.release_connection(client_ip)