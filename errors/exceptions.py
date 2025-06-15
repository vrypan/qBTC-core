"""
Custom exception classes for qBTC-core blockchain
"""

class BlockchainError(Exception):
    """Base exception for blockchain operations"""
    def __init__(self, message: str, code: str = None):
        super().__init__(message)
        self.message = message
        self.code = code or "BLOCKCHAIN_ERROR"

class ValidationError(BlockchainError):
    """Transaction or block validation failed"""
    def __init__(self, message: str):
        super().__init__(message, "VALIDATION_ERROR")

class NetworkError(BlockchainError):
    """Network-related errors"""
    def __init__(self, message: str):
        super().__init__(message, "NETWORK_ERROR")

class DatabaseError(BlockchainError):
    """Database operation errors"""
    def __init__(self, message: str):
        super().__init__(message, "DATABASE_ERROR")

class AuthenticationError(BlockchainError):
    """Authentication/authorization errors"""
    def __init__(self, message: str):
        super().__init__(message, "AUTH_ERROR")

class InsufficientFundsError(ValidationError):
    """Insufficient funds for transaction"""
    def __init__(self, required: str, available: str):
        message = f"Insufficient funds: need {required}, have {available}"
        super().__init__(message)
        self.required = required
        self.available = available

class InvalidSignatureError(ValidationError):
    """Invalid cryptographic signature"""
    def __init__(self, message: str = "Invalid signature"):
        super().__init__(message)

class RateLimitError(BlockchainError):
    """Rate limit exceeded"""
    def __init__(self, message: str = "Rate limit exceeded"):
        super().__init__(message, "RATE_LIMIT_ERROR")