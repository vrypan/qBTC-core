"""
Comprehensive tests for rate limiting and security implementation
"""

import pytest
import time
from unittest.mock import Mock

from security.advanced_rate_limiter import AdvancedRateLimiter, ThreatLevel, ClientInfo
from security.integrated_security import IntegratedSecurityMiddleware, security_metrics
from network.peer_reputation import PeerReputationManager, PeerBehavior
from errors.exceptions import RateLimitError


class TestAdvancedRateLimiter:
    """Test advanced rate limiter functionality"""
    
    def setup_method(self):
        """Setup test environment"""
        self.rate_limiter = AdvancedRateLimiter(enable_redis=False)
    
    def test_client_info_creation(self):
        """Test client info object creation and methods"""
        client = ClientInfo(
            ip="192.168.1.100",
            user_agent="test-agent",
            first_seen=time.time(),
            last_seen=time.time()
        )
        
        assert client.ip == "192.168.1.100"
        assert not client.is_blocked()
        assert client.threat_level == ThreatLevel.LOW
        
        # Test threat score calculation
        score = client.calculate_threat_score()
        assert 0 <= score <= 100
    
    def test_threat_level_calculation(self):
        """Test threat level calculation based on behavior"""
        client = ClientInfo(
            ip="192.168.1.100",
            user_agent="test-agent",
            first_seen=time.time() - 3600,  # 1 hour ago
            last_seen=time.time(),
            request_count=100,
            failed_requests=50  # 50% failure rate
        )
        
        client.update_threat_level()
        assert client.threat_level in [ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL]
    
    @pytest.mark.asyncio
    async def test_rate_limit_normal_requests(self):
        """Test rate limiter allows normal request patterns"""
        mock_request = Mock()
        mock_request.client.host = "192.168.1.100"
        mock_request.url.path = "/balance/test"
        mock_request.headers = {"user-agent": "test-client"}
        
        # Should allow several requests
        for _ in range(5):
            result = await self.rate_limiter.check_rate_limit(mock_request)
            assert result is True
    
    @pytest.mark.asyncio
    async def test_rate_limit_enforcement(self):
        """Test rate limiter blocks excessive requests"""
        mock_request = Mock()
        mock_request.client.host = "192.168.1.101"
        mock_request.url.path = "/worker"  # Low limit endpoint
        mock_request.headers = {"user-agent": "test-client"}
        
        # Make requests up to the limit - expecting rate limit at 8th request
        # The system has adaptive threat-based limiting
        rate_limit_hit = False
        try:
            for i in range(10):
                await self.rate_limiter.check_rate_limit(mock_request)
        except RateLimitError:
            rate_limit_hit = True
        
        # Should have hit rate limit before 10 requests
        assert rate_limit_hit, "Expected rate limit to be enforced"
    
    @pytest.mark.asyncio
    async def test_threat_based_limiting(self):
        """Test threat-based rate limit adjustment"""
        mock_request = Mock()
        mock_request.client.host = "192.168.1.102"
        mock_request.url.path = "/balance"
        mock_request.headers = {"user-agent": "test-client"}
        
        # Create high-threat client manually
        client_info = ClientInfo(
            ip="192.168.1.102",
            user_agent="test-client",
            first_seen=time.time(),
            last_seen=time.time(),
            request_count=1000,
            failed_requests=800  # High failure rate
        )
        client_info.update_threat_level()
        
        # Store in rate limiter
        self.rate_limiter.client_info["192.168.1.102"] = client_info
        
        # Should have reduced rate limit due to high threat
        with pytest.raises(RateLimitError):
            # Try to make requests that would be allowed for normal clients
            for _ in range(50):  # Normal limit is 100, but threat reduction should trigger
                await self.rate_limiter.check_rate_limit(mock_request)
    
    @pytest.mark.asyncio
    async def test_failed_request_recording(self):
        """Test recording of failed requests"""
        mock_request = Mock()
        mock_request.client.host = "192.168.1.103"
        mock_request.headers = {"user-agent": "test-client"}
        
        # Record multiple failures
        for _ in range(15):
            await self.rate_limiter.record_failed_request(mock_request, "test_error")
        
        # Client should be auto-blocked
        client_info = self.rate_limiter.client_info["192.168.1.103"]
        assert client_info.blocked_until > time.time()


class TestPeerReputationManager:
    """Test peer reputation system"""
    
    def setup_method(self):
        """Setup test environment"""
        self.reputation_manager = PeerReputationManager()
    
    def test_peer_addition(self):
        """Test adding new peers"""
        peer = self.reputation_manager.add_peer("192.168.1.200", 8333)
        
        assert peer.ip == "192.168.1.200"
        assert peer.port == 8333
        assert peer.behavior == PeerBehavior.GOOD
        assert peer.reputation_score == 100.0
    
    def test_connection_success_recording(self):
        """Test recording successful connections"""
        self.reputation_manager.record_connection_success("192.168.1.201", 8333)
        
        peer = self.reputation_manager.get_peer_reputation("192.168.1.201", 8333)
        assert peer.successful_connections == 1
        assert peer.behavior == PeerBehavior.GOOD
    
    def test_invalid_message_handling(self):
        """Test handling of invalid messages"""
        # Record multiple invalid messages
        for _ in range(15):
            self.reputation_manager.record_invalid_message("192.168.1.202", 8333, "test_error")
        
        peer = self.reputation_manager.get_peer_reputation("192.168.1.202", 8333)
        assert peer.invalid_messages == 15
        # Security system automatically bans peers with excessive violations
        assert peer.behavior in [PeerBehavior.SUSPICIOUS, PeerBehavior.MALICIOUS, PeerBehavior.BANNED]
    
    def test_spam_detection(self):
        """Test spam message detection"""
        # Record spam messages
        for _ in range(6):
            self.reputation_manager.record_spam_message("192.168.1.203", 8333)
        
        peer = self.reputation_manager.get_peer_reputation("192.168.1.203", 8333)
        assert peer.spam_messages == 6
        assert peer.behavior == PeerBehavior.MALICIOUS
    
    def test_peer_banning(self):
        """Test peer banning functionality"""
        self.reputation_manager.ban_peer("192.168.1.204", 8333, 3600, "test_ban")
        
        peer = self.reputation_manager.get_peer_reputation("192.168.1.204", 8333)
        assert peer.is_banned()
        assert peer.behavior == PeerBehavior.BANNED
        
        # Should not allow connection to banned peer
        assert not self.reputation_manager.should_connect_to_peer("192.168.1.204", 8333)
    
    def test_reputation_score_calculation(self):
        """Test reputation score calculation"""
        # Create peer with mixed behavior
        peer = self.reputation_manager.add_peer("192.168.1.205", 8333)
        
        # Record good behavior
        for _ in range(10):
            self.reputation_manager.record_valid_message("192.168.1.205", 8333, "transaction")
            self.reputation_manager.record_connection_success("192.168.1.205", 8333)
        
        # Record some bad behavior
        for _ in range(2):
            self.reputation_manager.record_invalid_message("192.168.1.205", 8333, "test")
        
        peer = self.reputation_manager.get_peer_reputation("192.168.1.205", 8333)
        assert 50 < peer.reputation_score <= 100  # Should still be good overall
    
    def test_trusted_peers_selection(self):
        """Test trusted peer selection"""
        # Create multiple peers with different reputations
        for i in range(5):
            ip = f"192.168.1.{210 + i}"
            peer = self.reputation_manager.add_peer(ip, 8333)
            
            # Give different reputation scores
            if i < 2:
                # High reputation peers
                for _ in range(50):
                    self.reputation_manager.record_valid_message(ip, 8333, "block")
                # Make them older
                peer.first_seen = time.time() - 7200  # 2 hours ago
            else:
                # Lower reputation peers
                for _ in range(10):
                    self.reputation_manager.record_invalid_message(ip, 8333, "test")
        
        trusted = self.reputation_manager.get_trusted_peers()
        assert len(trusted) >= 2  # Should have at least the high reputation peers


class TestIntegratedSecurityMiddleware:
    """Test integrated security middleware"""
    
    def setup_method(self):
        """Setup test environment"""
        self.middleware = IntegratedSecurityMiddleware()
        security_metrics.reset_metrics()
    
    def test_attack_pattern_detection(self):
        """Test detection of common attack patterns"""
        # SQL injection attempt
        mock_request = Mock()
        mock_request.url = Mock()
        mock_request.url.path = "/api/test"
        mock_request.query_params = {}
        # Mock the URL string conversion to include SQL injection pattern
        mock_request.url.__str__ = lambda self: "http://test.com/api/test?id=1' or 1=1"
        
        attack = self.middleware._detect_attack_patterns(mock_request)
        assert attack is not None
        assert "sql_injection" in attack
    
    def test_bot_detection(self):
        """Test automated request detection"""
        mock_request = Mock()
        mock_request.headers = {"user-agent": "python-requests/2.28.0"}
        
        is_bot = self.middleware._is_automated_request(mock_request)
        assert is_bot is True
        
        # Test normal browser
        mock_request.headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.5",
            "accept-encoding": "gzip, deflate"
        }
        
        is_bot = self.middleware._is_automated_request(mock_request)
        assert is_bot is False
    
    def test_client_info_extraction(self):
        """Test client information extraction"""
        mock_request = Mock()
        mock_request.client.host = "192.168.1.100"
        mock_request.headers = {
            "user-agent": "test-client",
            "x-forwarded-for": "203.0.113.100, 192.168.1.100"
        }
        mock_request.method = "GET"
        mock_request.url.path = "/api/test"
        mock_request.query_params = {}
        
        client_info = self.middleware._get_client_info(mock_request)
        
        assert client_info['ip'] == "203.0.113.100"  # Should use forwarded IP
        assert client_info['user_agent'] == "test-client"
        assert client_info['method'] == "GET"


class TestSecurityIntegration:
    """Integration tests for complete security system"""
    
    @pytest.mark.asyncio
    async def test_security_metrics_tracking(self):
        """Test security metrics are properly tracked"""
        initial_metrics = security_metrics.get_metrics()
        
        # Simulate some security events
        security_metrics.record_request("192.168.1.100", "/api/test", "success")
        security_metrics.record_request("192.168.1.101", "/api/test", "blocked")
        security_metrics.record_request("192.168.1.102", "/api/test", "rate_limited")
        
        updated_metrics = security_metrics.get_metrics()
        
        assert updated_metrics['total_requests'] == initial_metrics['total_requests'] + 3
        assert updated_metrics['blocked_requests'] == initial_metrics['blocked_requests'] + 1
        assert updated_metrics['rate_limited_requests'] == initial_metrics['rate_limited_requests'] + 1
    
    def test_security_status_reporting(self):
        """Test security status reporting functionality"""
        # This would require async testing in a real scenario
        # For now, test the data structures are correct
        
        from security.integrated_security import get_security_status
        
        # Test that the function exists and has correct structure
        import inspect
        assert inspect.iscoroutinefunction(get_security_status)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])