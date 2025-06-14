"""
Structured logging system for qBTC-core
"""

import logging
import json
import sys
import time
import asyncio
from typing import Dict, Any, Optional
from datetime import datetime

class StructuredFormatter(logging.Formatter):
    """Custom formatter for structured JSON logging"""
    
    def format(self, record: logging.LogRecord) -> str:
        # Base log structure
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        # Add correlation ID if available
        if hasattr(record, 'correlation_id'):
            log_entry["correlation_id"] = record.correlation_id
        
        # Add request context if available
        if hasattr(record, 'client_ip'):
            log_entry["client_ip"] = record.client_ip
        
        if hasattr(record, 'endpoint'):
            log_entry["endpoint"] = record.endpoint
        
        if hasattr(record, 'method'):
            log_entry["method"] = record.method
        
        # Add blockchain context
        if hasattr(record, 'block_hash'):
            log_entry["block_hash"] = record.block_hash
        
        if hasattr(record, 'tx_id'):
            log_entry["tx_id"] = record.tx_id
        
        if hasattr(record, 'peer_id'):
            log_entry["peer_id"] = record.peer_id
        
        # Add performance metrics
        if hasattr(record, 'process_time'):
            log_entry["process_time"] = record.process_time
        
        if hasattr(record, 'status_code'):
            log_entry["status_code"] = record.status_code
        
        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": self.formatException(record.exc_info)
            }
        
        # Add any extra fields from the record
        extra_fields = {}
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname', 
                          'filename', 'module', 'exc_info', 'exc_text', 'stack_info',
                          'lineno', 'funcName', 'created', 'msecs', 'relativeCreated',
                          'thread', 'threadName', 'processName', 'process', 'getMessage',
                          'correlation_id', 'client_ip', 'endpoint', 'method', 'block_hash',
                          'tx_id', 'peer_id', 'process_time', 'status_code']:
                extra_fields[key] = value
        
        if extra_fields:
            log_entry["extra"] = extra_fields
        
        return json.dumps(log_entry, default=str)

class ContextualLogger:
    """Logger with contextual information"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.context: Dict[str, Any] = {}
    
    def with_context(self, **kwargs) -> 'ContextualLogger':
        """Create a new logger instance with additional context"""
        new_logger = ContextualLogger(self.logger)
        new_logger.context = {**self.context, **kwargs}
        return new_logger
    
    def _log(self, level: int, msg: str, *args, **kwargs):
        """Internal logging method that adds context"""
        extra = kwargs.get('extra', {})
        extra.update(self.context)
        kwargs['extra'] = extra
        self.logger.log(level, msg, *args, **kwargs)
    
    def debug(self, msg: str, *args, **kwargs):
        self._log(logging.DEBUG, msg, *args, **kwargs)
    
    def info(self, msg: str, *args, **kwargs):
        self._log(logging.INFO, msg, *args, **kwargs)
    
    def warning(self, msg: str, *args, **kwargs):
        self._log(logging.WARNING, msg, *args, **kwargs)
    
    def error(self, msg: str, *args, **kwargs):
        self._log(logging.ERROR, msg, *args, **kwargs)
    
    def critical(self, msg: str, *args, **kwargs):
        self._log(logging.CRITICAL, msg, *args, **kwargs)

def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    enable_console: bool = True,
    enable_structured: bool = True
) -> ContextualLogger:
    """Setup structured logging for the application"""
    
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Choose formatter
    if enable_structured:
        formatter = StructuredFormatter()
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    # Console handler
    if enable_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, level.upper()))
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(getattr(logging, level.upper()))
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    
    # Return contextual logger
    return ContextualLogger(root_logger)

# Performance monitoring decorator
def log_performance(logger: ContextualLogger, operation: str):
    """Decorator to log performance metrics"""
    def decorator(func):
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                duration = time.time() - start_time
                logger.info(
                    f"Operation completed: {operation}",
                    extra={
                        "operation": operation,
                        "duration": duration,
                        "status": "success"
                    }
                )
                return result
            except Exception as e:
                duration = time.time() - start_time
                logger.error(
                    f"Operation failed: {operation}",
                    extra={
                        "operation": operation,
                        "duration": duration,
                        "status": "error",
                        "error": str(e)
                    }
                )
                raise
        
        def sync_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time
                logger.info(
                    f"Operation completed: {operation}",
                    extra={
                        "operation": operation,
                        "duration": duration,
                        "status": "success"
                    }
                )
                return result
            except Exception as e:
                duration = time.time() - start_time
                logger.error(
                    f"Operation failed: {operation}",
                    extra={
                        "operation": operation,
                        "duration": duration,
                        "status": "error",
                        "error": str(e)
                    }
                )
                raise
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    return decorator

# Module-specific loggers
def get_logger(name: str) -> ContextualLogger:
    """Get a contextual logger for a specific module"""
    return ContextualLogger(logging.getLogger(name))