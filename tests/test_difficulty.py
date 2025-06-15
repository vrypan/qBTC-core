"""
Tests for difficulty adjustment algorithm
"""
import pytest
from blockchain.difficulty import (
    compact_to_target, target_to_compact, calculate_next_bits,
    validate_block_bits, validate_block_timestamp,
    MAX_TARGET_BITS, MIN_TARGET_BITS, MAX_ADJUSTMENT_FACTOR, MIN_ADJUSTMENT_FACTOR
)
from config.config import DIFFICULTY_ADJUSTMENT_INTERVAL, BLOCK_TIME_TARGET


class TestDifficultyConversion:
    """Test compact bits <-> target conversion"""
    
    def test_compact_to_target_min_difficulty(self):
        """Test minimum difficulty (max target)"""
        bits = 0x1d00ffff
        target = compact_to_target(bits)
        # This should be approximately 2^224 - 1
        assert target == 0x00000000ffff0000000000000000000000000000000000000000000000000000
    
    def test_compact_to_target_basic(self):
        """Test basic compact to target conversion"""
        # Just verify it produces reasonable values
        bits = 0x1d00ffff
        target = compact_to_target(bits)
        assert target > 0
        assert target < (1 << 256)  # Should be less than max 256-bit value
    
    def test_target_to_compact_roundtrip(self):
        """Test that converting back and forth preserves value"""
        test_bits = [0x1d00ffff, 0x1b0404cb, 0x1a0fffff, 0x1c0fffff]
        
        for original_bits in test_bits:
            target = compact_to_target(original_bits)
            recovered_bits = target_to_compact(target)
            assert recovered_bits == original_bits


class TestDifficultyAdjustment:
    """Test difficulty adjustment calculations"""
    
    def test_no_adjustment_when_on_target(self):
        """When blocks come exactly on time, difficulty shouldn't change"""
        last_bits = 0x1d00ffff
        expected_time = BLOCK_TIME_TARGET * (DIFFICULTY_ADJUSTMENT_INTERVAL - 1)
        
        # Blocks came exactly on schedule
        first_timestamp = 1000000
        last_timestamp = first_timestamp + expected_time
        
        new_bits = calculate_next_bits(last_bits, first_timestamp, last_timestamp)
        
        # Should be the same (or very close due to rounding)
        assert new_bits == last_bits
    
    def test_difficulty_increases_when_too_fast(self):
        """When blocks come too fast, difficulty should increase"""
        last_bits = 0x1c00ffff  # Use a difficulty that can increase
        expected_time = BLOCK_TIME_TARGET * (DIFFICULTY_ADJUSTMENT_INTERVAL - 1)
        
        # Blocks came twice as fast
        first_timestamp = 1000000
        last_timestamp = first_timestamp + (expected_time // 2)
        
        new_bits = calculate_next_bits(last_bits, first_timestamp, last_timestamp)
        
        # When difficulty increases, target decreases
        old_target = compact_to_target(last_bits)
        new_target = compact_to_target(new_bits)
        
        # Target should decrease (making mining harder)
        assert new_target < old_target, f"Target should decrease when blocks are too fast. Old: {old_target}, New: {new_target}"
        
        # Verify difficulty actually increased
        old_difficulty = (1 << 256) / old_target
        new_difficulty = (1 << 256) / new_target
        assert new_difficulty > old_difficulty, f"Difficulty should increase. Old: {old_difficulty}, New: {new_difficulty}"
    
    def test_difficulty_decreases_when_too_slow(self):
        """When blocks come too slow, difficulty should decrease"""
        last_bits = 0x1b00ffff  # Use a difficulty that can decrease
        expected_time = BLOCK_TIME_TARGET * (DIFFICULTY_ADJUSTMENT_INTERVAL - 1)
        
        # Blocks came twice as slow
        first_timestamp = 1000000
        last_timestamp = first_timestamp + (expected_time * 2)
        
        new_bits = calculate_next_bits(last_bits, first_timestamp, last_timestamp)
        
        # When difficulty decreases, target increases
        old_target = compact_to_target(last_bits)
        new_target = compact_to_target(new_bits)
        
        # Target should increase (making mining easier)
        assert new_target > old_target, f"Target should increase when blocks are too slow. Old: {old_target}, New: {new_target}"
        
        # Verify difficulty actually decreased
        old_difficulty = (1 << 256) / old_target
        new_difficulty = (1 << 256) / new_target
        assert new_difficulty < old_difficulty, f"Difficulty should decrease. Old: {old_difficulty}, New: {new_difficulty}"
    
    def test_max_adjustment_factor(self):
        """Test that adjustment is capped at 4x"""
        last_bits = 0x1d00ffff
        expected_time = BLOCK_TIME_TARGET * (DIFFICULTY_ADJUSTMENT_INTERVAL - 1)
        
        # Blocks came 10x too fast (should cap at 4x)
        first_timestamp = 1000000
        last_timestamp = first_timestamp + (expected_time // 10)
        
        new_bits = calculate_next_bits(last_bits, first_timestamp, last_timestamp)
        
        # Check that adjustment was capped
        old_target = compact_to_target(last_bits)
        new_target = compact_to_target(new_bits)
        ratio = old_target / new_target  # Inverse because lower target = higher difficulty
        
        assert ratio <= MAX_ADJUSTMENT_FACTOR + 0.01  # Small tolerance for rounding
    
    def test_min_adjustment_factor(self):
        """Test that adjustment is capped at 1/4x"""
        last_bits = 0x1d00ffff
        expected_time = BLOCK_TIME_TARGET * (DIFFICULTY_ADJUSTMENT_INTERVAL - 1)
        
        # Blocks came 10x too slow (should cap at 4x easier)
        first_timestamp = 1000000
        last_timestamp = first_timestamp + (expected_time * 10)
        
        new_bits = calculate_next_bits(last_bits, first_timestamp, last_timestamp)
        
        # Check that adjustment was capped
        old_target = compact_to_target(last_bits)
        new_target = compact_to_target(new_bits)
        ratio = new_target / old_target  # Normal ratio because higher target = lower difficulty
        
        assert ratio <= MAX_ADJUSTMENT_FACTOR + 0.01  # Small tolerance for rounding
    
    def test_negative_time_protection(self):
        """Test that negative time doesn't break the algorithm"""
        last_bits = 0x1d00ffff
        
        # Timestamps in wrong order
        first_timestamp = 1000000
        last_timestamp = first_timestamp - 100  # Earlier than first!
        
        # Should not crash and should use expected time
        new_bits = calculate_next_bits(last_bits, first_timestamp, last_timestamp)
        
        # Should be same as no adjustment
        assert new_bits == last_bits


class TestBlockValidation:
    """Test block validation functions"""
    
    def test_validate_correct_bits(self):
        """Test that correct bits pass validation"""
        assert validate_block_bits(0x1d00ffff, 0x1d00ffff) == True
    
    def test_validate_incorrect_bits(self):
        """Test that incorrect bits fail validation"""
        assert validate_block_bits(0x1d00ffff, 0x1c00ffff) == False
    
    def test_validate_timestamp_normal(self):
        """Test normal timestamp validation"""
        previous_timestamp = 1000000
        current_time = 1001000
        
        # Valid: greater than previous and not too far in future
        assert validate_block_timestamp(1000500, previous_timestamp, current_time) == True
    
    def test_validate_timestamp_not_greater(self):
        """Test timestamp must be greater than previous"""
        previous_timestamp = 1000000
        current_time = 1001000
        
        # Same as previous - invalid
        assert validate_block_timestamp(1000000, previous_timestamp, current_time) == False
        
        # Earlier than previous - invalid
        assert validate_block_timestamp(999999, previous_timestamp, current_time) == False
    
    def test_validate_timestamp_too_future(self):
        """Test timestamp too far in future"""
        previous_timestamp = 1000000
        current_time = 1001000
        
        # More than 2 hours in future
        future_timestamp = current_time + (3 * 60 * 60)
        assert validate_block_timestamp(future_timestamp, previous_timestamp, current_time) == False
    
    def test_validate_timestamp_edge_cases(self):
        """Test timestamp edge cases"""
        previous_timestamp = 1000000
        current_time = 1001000
        
        # Exactly 2 hours in future (should be valid)
        edge_future = current_time + (2 * 60 * 60)
        assert validate_block_timestamp(edge_future, previous_timestamp, current_time) == True
        
        # Just over 2 hours in future (should be invalid)
        over_future = current_time + (2 * 60 * 60) + 1
        assert validate_block_timestamp(over_future, previous_timestamp, current_time) == False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])