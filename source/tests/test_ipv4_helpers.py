
import unittest

from mojo.networking.resolution import is_ipv4_address

class TestIpv4HelpersPositive(unittest.TestCase):

    def test_is_ipv4_address_min(self):
        candidate = "0.0.0.0"
        result = is_ipv4_address(candidate)
        assert result, "The address={candidate} should have validated as a valid address."
        return
    
    def test_is_ipv4_address_max(self):
        candidate = "255.255.255.255"
        result = is_ipv4_address(candidate)
        assert result, "The address={candidate} should have validated as a valid address."
        return

    def test_is_ipv4_address_v1(self):
        candidate = "100.100.100.100"
        result = is_ipv4_address(candidate)
        assert result, "The address={candidate} should have validated as a valid address."
        return
    
    def test_is_ipv4_address_v2(self):
        candidate = "1.1.1.1"
        result = is_ipv4_address(candidate)
        assert result, "The address={candidate} should have validated as a valid address."
        return


class TestIpv4HelpersNegative(unittest.TestCase):

    def test_is_ipv4_address_minus_one(self):
        candidate = "-1.-1.-1.-1"
        result = is_ipv4_address(candidate)
        assert not result, "The address={candidate} should NOT have validated as a valid address."
        return
    
    def test_is_ipv4_address_plus_one(self):
        candidate = "256.256.256.256"
        result = is_ipv4_address(candidate)
        assert not result, "The address={candidate} should NOT have validated as a valid address."
        return

    def test_is_ipv4_address_too_few_groups(self):
        candidate = "100.100.100"
        result = is_ipv4_address(candidate)
        assert not result, "The address={candidate} should NOT have validated as a valid address."
        return
    
    def test_is_ipv4_address_too_many_groups(self):
        candidate = "1.1.1.1.1"
        result = is_ipv4_address(candidate)
        assert not result, "The address={candidate} should NOT have validated as a valid address."
        return


if __name__ == '__main__':
    unittest.main()