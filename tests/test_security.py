"""
Security tests for qBTC-core Phase 1 implementation
"""

import pytest
import base64
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch

from web.web import app
from errors.exceptions import RateLimitError
from models.validation import TransactionRequest
from security.rate_limiter import RateLimiter


class TestInputValidation:
    """Test input validation security measures"""
    
    def test_transaction_request_validation_valid(self):
        """Test valid transaction request passes validation"""
        # Create valid base64 encoded data
        message = "bqs1senderwallet000000000000000000000000:bqs1receiverwallet00000000000000000000000:10.5"
        signature = "fake_signature_data"
        pubkey = "fake_pubkey_data"
        
        tx_request = TransactionRequest(
            message=base64.b64encode(message.encode()).decode(),
            signature=base64.b64encode(signature.encode()).decode(),
            pubkey=base64.b64encode(pubkey.encode()).decode()
        )
        
        assert tx_request.message is not None
        assert tx_request.signature is not None
        assert tx_request.pubkey is not None
    
    def test_transaction_request_validation_invalid_base64(self):
        """Test invalid base64 encoding is rejected"""
        with pytest.raises(ValueError, match="Must be valid base64"):
            TransactionRequest(
                message="invalid_base64!@#",
                signature=base64.b64encode(b"sig").decode(),
                pubkey=base64.b64encode(b"pub").decode()
            )
    
    def test_transaction_request_validation_invalid_message_format(self):
        """Test invalid message format is rejected"""
        # Missing required parts
        invalid_message = "invalid_format"
        
        with pytest.raises(ValueError, match="Message must have format"):
            TransactionRequest(
                message=base64.b64encode(invalid_message.encode()).decode(),
                signature=base64.b64encode(b"sig").decode(),
                pubkey=base64.b64encode(b"pub").decode()
            )
    
    def test_transaction_request_validation_invalid_address(self):
        """Test invalid address format is rejected"""
        # Invalid sender address
        invalid_message = "invalid_address:bqs456receiver:10.5"
        
        with pytest.raises(ValueError, match="Invalid sender address"):
            TransactionRequest(
                message=base64.b64encode(invalid_message.encode()).decode(),
                signature=base64.b64encode(b"sig").decode(),
                pubkey=base64.b64encode(b"pub").decode()
            )
    
    def test_transaction_request_validation_invalid_amount(self):
        """Test invalid amount is rejected"""
        # Negative amount
        invalid_message = "bqs1senderwallet000000000000000000000000:bqs1receiverwallet00000000000000000000000:-10.5"
        
        with pytest.raises(ValueError, match="Invalid amount format"):
            TransactionRequest(
                message=base64.b64encode(invalid_message.encode()).decode(),
                signature=base64.b64encode(b"sig").decode(),
                pubkey=base64.b64encode(b"pub").decode()
            )
        
        # Amount too large  
        large_amount_message = "bqs1senderwallet000000000000000000000000:bqs1receiverwallet00000000000000000000000:50000000"
        
        with pytest.raises(ValueError, match="Invalid amount format"):
            TransactionRequest(
                message=base64.b64encode(large_amount_message.encode()).decode(),
                signature=base64.b64encode(b"sig").decode(),
                pubkey=base64.b64encode(b"pub").decode()
            )


class TestRateLimiting:
    """Test rate limiting functionality"""
    
    def setup_method(self):
        """Setup test environment"""
        self.rate_limiter = RateLimiter()
    
    def test_rate_limiter_allows_normal_requests(self):
        """Test rate limiter allows normal request patterns"""
        # Mock request
        mock_request = Mock()
        mock_request.client.host = "192.168.1.100"
        mock_request.url.path = "/balance/test"
        mock_request.headers = {}
        
        # Should allow first request
        result = self.rate_limiter.check_rate_limit(mock_request)
        assert result is True
    
    def test_rate_limiter_blocks_excessive_requests(self):
        """Test rate limiter blocks excessive requests"""
        mock_request = Mock()
        mock_request.client.host = "192.168.1.100"
        mock_request.url.path = "/worker"  # Lower limit endpoint
        mock_request.headers = {}
        
        # Make requests up to the limit
        for _ in range(10):
            self.rate_limiter.check_rate_limit(mock_request)
        
        # Next request should be rate limited
        with pytest.raises(RateLimitError):
            self.rate_limiter.check_rate_limit(mock_request)
    
    def test_rate_limiter_different_endpoints_different_limits(self):
        """Test different endpoints have different rate limits"""
        mock_request_worker = Mock()
        mock_request_worker.client.host = "192.168.1.100"
        mock_request_worker.url.path = "/worker"
        mock_request_worker.headers = {}
        
        mock_request_balance = Mock()
        mock_request_balance.client.host = "192.168.1.100"
        mock_request_balance.url.path = "/balance/test"
        mock_request_balance.headers = {}
        
        # Worker endpoint has lower limit (10)
        for _ in range(10):
            self.rate_limiter.check_rate_limit(mock_request_worker)
        
        # Should still allow balance requests (higher limit)
        result = self.rate_limiter.check_rate_limit(mock_request_balance)
        assert result is True


class TestAPIEndpoints:
    """Test API endpoint security"""
    
    def setup_method(self):
        """Setup test client"""
        self.client = TestClient(app)
        # Set up required gossip client for security middleware
        from unittest.mock import Mock
        app.state.gossip_client = Mock()
    
    @patch('web.web.get_balance')
    def test_balance_endpoint_validates_address(self, mock_get_balance):
        """Test balance endpoint validates wallet address"""
        mock_get_balance.return_value = "100.0"
        
        # Valid address
        response = self.client.get("/balance/bqs1validaddress000000000000000000000000")
        assert response.status_code == 200
        
        # Invalid address (doesn't start with bqs)
        response = self.client.get("/balance/invalid_address")
        assert response.status_code == 400
        assert "error" in response.json()
    
    @patch('web.web.get_transactions')
    def test_transactions_endpoint_validates_limit(self, mock_get_transactions):
        """Test transactions endpoint validates limit parameter"""
        mock_get_transactions.return_value = []
        
        # Valid limit
        response = self.client.get("/transactions/bqs1validaddress000000000000000000000000?limit=50")
        assert response.status_code == 200
        
        # Invalid limit (too high)
        response = self.client.get("/transactions/bqs1validaddress000000000000000000000000?limit=5000")
        assert response.status_code == 400
        assert "error" in response.json()
        
        # Invalid limit (negative)
        response = self.client.get("/transactions/bqs1validaddress000000000000000000000000?limit=-10")
        assert response.status_code == 400
    
    def test_worker_endpoint_validates_json(self):
        """Test worker endpoint validates JSON input"""
        # Invalid JSON
        response = self.client.post("/worker", content="invalid json")
        assert response.status_code == 400
        
        # Missing request_type
        response = self.client.post("/worker", json={"data": "test"})
        assert response.status_code == 400
    
    @patch('web.web.health_monitor')
    def test_health_endpoint_returns_structured_response(self, mock_health_monitor):
        """Test health endpoint returns Prometheus metrics"""
        # Mock the async run_health_checks
        from unittest.mock import AsyncMock
        mock_health_monitor.run_health_checks = AsyncMock(return_value=None)
        
        # Mock generate_metrics to return Prometheus format
        mock_health_monitor.generate_metrics.return_value = (
            "# HELP qbtc_uptime_seconds Node uptime in seconds\n"
            "# TYPE qbtc_uptime_seconds gauge\n"
            "qbtc_uptime_seconds 100.0\n",
            "text/plain; version=0.0.4"
        )
        
        response = self.client.get("/health")
        assert response.status_code == 200
        
        # Check it's Prometheus format not JSON
        assert response.headers["content-type"].startswith("text/plain; version=0.0.4")
        assert "qbtc_uptime_seconds" in response.text
        assert "# HELP" in response.text
        assert "# TYPE" in response.text


class TestErrorHandling:
    """Test error handling middleware"""
    
    def test_validation_error_returns_structured_response(self):
        """Test validation errors return structured response format"""
        client = TestClient(app)
        # Set up required gossip client for security middleware
        from unittest.mock import Mock
        app.state.gossip_client = Mock()
        
        # Trigger validation error with invalid address
        response = client.get("/balance/invalid")
        
        assert response.status_code == 400
        error_data = response.json()
        
        # Check error structure
        assert "error" in error_data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])