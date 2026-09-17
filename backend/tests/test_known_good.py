import pytest

from app.known_good import check_domain, check_ip


@pytest.mark.parametrize("ip", ["10.1.2.3", "192.168.0.10", "127.0.0.1", "172.16.5.5", "fe80::1"])
def test_private_addresses_are_never_sent_out(ip):
    result = check_ip(ip)
    assert result.skip_external_lookup and not result.is_known_good


def test_public_resolver_is_known_good():
    assert check_ip("8.8.8.8").is_known_good
    assert not check_ip("45.95.147.236").is_known_good


@pytest.mark.parametrize("domain", ["microsoft.com", "update.microsoft.com", "github.com"])
def test_well_known_domains(domain):
    assert check_domain(domain).is_known_good


@pytest.mark.parametrize("domain", ["evil.github.io", "drive.google.com", "phish.pages.dev"])
def test_user_content_platforms_are_not_trusted(domain):
    result = check_domain(domain)
    assert not result.is_known_good and result.caution


def test_lookalike_domains_are_not_trusted():
    assert not check_domain("microsoft.com.evil.ru").is_known_good
    assert not check_domain("notmicrosoft.com").is_known_good
