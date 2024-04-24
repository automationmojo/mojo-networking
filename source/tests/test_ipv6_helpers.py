import unittest

from mojo.networking.resolution import expand_ipv6_addr, is_ipv6_address

class TestIpv6HelpersPositive(unittest.TestCase):

    def test_is_ipv6_check_address_min(self):
        candidate = "0:0:0:0:0:0:0:0"
        result = is_ipv6_address(candidate)
        assert result, "The address={candidate} should have validated as a valid address."
        return
    
    def test_is_ipv6_check_address_max(self):
        candidate = "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"
        result = is_ipv6_address(candidate)
        assert result, "The address={candidate} should have validated as a valid address."
        return
    
    def test_is_ipv6_check_address_exp_middle(self):
        candidate = "FFFF:FFFF::FFFF:FFFF:FFFF"
        result = is_ipv6_address(candidate)
        assert result, "The address={candidate} should have validated as a valid address."
        return

    def test_is_ipv6_check_address_exp_pre(self):
        candidate = "::FFFF:FFFF:FFFF:FFFF:FFFF"
        result = is_ipv6_address(candidate)
        assert result, "The address={candidate} should have validated as a valid address."
        return
    
    def test_is_ipv6_check_address_exp_post(self):
        candidate = "FFFF:FFFF:FFFF:FFFF:FFFF::"
        result = is_ipv6_address(candidate)
        assert result, "The address={candidate} should have validated as a valid address."
        return
    
    def test_is_ipv6_expand_address_pre(self):
        candidate = "::FFFF:FFFF:FFFF:FFFF"
        expected = "0:0:0:0:FFFF:FFFF:FFFF:FFFF"
        result = expand_ipv6_addr(candidate)
        assert result == expected, f"The address={candidate} should have expanded to found={expected}."
        return
    
    def test_is_ipv6_expand_address_post(self):
        candidate = "FFFF:FFFF:FFFF:FFFF:FFFF::"
        expected = "FFFF:FFFF:FFFF:FFFF:FFFF:0:0:0"
        result = expand_ipv6_addr(candidate)
        assert result == expected, f"The address={candidate} should have expanded to found={expected}."
        return
    
    def test_is_ipv6_expand_address_middle(self):
        candidate = "FFFF:FFFF::FFFF:FFFF"
        expected = "FFFF:FFFF:0:0:0:0:FFFF:FFFF"
        result = expand_ipv6_addr(candidate)
        assert result == expected, f"The address={candidate} should have expanded to found={expected}."
        return
    

    
if __name__ == '__main__':
    unittest.main()
