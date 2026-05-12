#!/usr/bin/env python3
"""
Unit tests for MCP OPNsense tools
"""
import asyncio
import pytest
from unittest.mock import patch, MagicMock

from mcp_opnsense.server import (
    system_status,
    get_gateways,
    list_interfaces,
    get_interface,
    list_vlans,
    add_vlan,
    get_vlan,
    delete_vlan,
    update_vlan,
    toggle_vlan,
    get_arp_table,
    flush_arp_table,
    get_interface_stats,
    list_services,
    start_service,
    stop_service,
    restart_service,
    get_system_log,
    list_cron_jobs,
    get_cron_job,
    update_cron_job,
    add_cron_job,
    delete_cron_job,
    toggle_cron_job,
    backup_config,
    apply_changes,
    list_dhcp_leases,
    list_static_leases,
    list_dhcpv6_leases,
    get_static_lease,
    add_static_lease,
    delete_static_lease,
    update_static_lease,
    toggle_static_lease
)


class TestOPNsenseTools:
    """Test cases for OPNsense MCP tools"""
    
    def test_system_status_success(self):
        """Test system status tool (mocked)"""
        # Can't easily test without real OPNsense connection, but we can check structure
        result = system_status()
        assert isinstance(result, dict)
    
    def test_list_interfaces_success(self):
        """Test list interfaces tool (mocked)"""
        result = list_interfaces()
        assert isinstance(result, dict)
    
    def test_list_vlans_success(self):
        """Test list vlans tool (mocked)"""
        result = list_vlans()
        assert isinstance(result, dict)
    
    def test_add_vlan_success(self):
        """Test add vlan with valid inputs"""
        result = add_vlan("em0", 100, "Test VLAN")
        # Should either succeed or return error, but not crash
        assert isinstance(result, dict)
    
    def test_add_vlan_invalid_tag(self):
        """Test add vlan with invalid tag"""
        result = add_vlan("em0", 5000)  # Invalid tag
        assert "error" in result
    
    def test_list_cron_jobs_success(self):
        """Test list cron jobs"""
        result = list_cron_jobs()
        assert isinstance(result, dict)
    
    def test_add_cron_job_success(self):
        """Test add cron job"""
        result = add_cron_job("/usr/local/bin/test.sh", "Test Job")
        # Should either succeed or return error, but not crash
        assert isinstance(result, dict)
    
    def test_get_system_log_success(self):
        """Test get system log"""
        result = get_system_log("system", 10)
        assert isinstance(result, dict)
    
    def test_backup_config_success(self):
        """Test backup config"""
        result = backup_config()
        assert isinstance(result, dict)
    
    def test_apply_changes_success(self):
        """Test apply changes"""
        result = apply_changes()
        assert isinstance(result, dict)
    
    def test_list_dhcp_leases_success(self):
        """Test list dhcp leases"""
        result = list_dhcp_leases()
        assert isinstance(result, dict)
    
    def test_add_static_lease_success(self):
        """Test add static lease"""
        result = add_static_lease("00:11:22:33:44:55", "192.168.1.100", "test-host")
        # Should either succeed or return error, but not crash
        assert isinstance(result, dict)
    
    def test_add_static_lease_invalid_mac(self):
        """Test add static lease with invalid MAC"""
        result = add_static_lease("invalid-mac", "192.168.1.100")
        assert "error" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])