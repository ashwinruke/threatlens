import pytest

from app.detection import DetectionError, detect, refang
from app.models import IndicatorType


@pytest.mark.parametrize("raw, kind, value, subtype", [
    ("CVE-2021-44228", IndicatorType.CVE, "CVE-2021-44228", None),
    ("  cve-2024-3094 ", IndicatorType.CVE, "CVE-2024-3094", None),
    ("8.8.8.8", IndicatorType.IP, "8.8.8.8", "ipv4"),
    ("203.0.113.9:443", IndicatorType.IP, "203.0.113.9", "ipv4"),
    ("2001:4860:4860::8888", IndicatorType.IP, "2001:4860:4860::8888", "ipv6"),
    ("[2001:db8::1]:8443", IndicatorType.IP, "2001:db8::1", "ipv6"),
    ("Example.COM.", IndicatorType.DOMAIN, "example.com", None),
    ("www.example.org", IndicatorType.DOMAIN, "example.org", None),
    ("bücher.de", IndicatorType.DOMAIN, "xn--bcher-kva.de", None),
    ("D41D8CD98F00B204E9800998ECF8427E", IndicatorType.HASH, "d41d8cd98f00b204e9800998ecf8427e", "md5"),
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", IndicatorType.HASH, "da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1"),
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", IndicatorType.HASH,
     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"),
])
def test_detects_types(raw, kind, value, subtype):
    indicator = detect(raw)
    assert (indicator.type, indicator.value, indicator.subtype) == (kind, value, subtype)
    assert indicator.original == raw


@pytest.mark.parametrize("raw, value", [
    ("hxxps://evil[.]com/payload.exe", "evil.com"),
    ("hXXp[:]//bad(dot)net", "bad.net"),
    ("198[.]51[.]100[.]7", "198.51.100.7"),
    ("user[@]phish[.]co", "phish.co"),
])
def test_refangs_and_extracts_host(raw, value):
    indicator = detect(raw)
    assert indicator.value == value
    assert indicator.refanged


def test_refang_leaves_normal_words_alone():
    assert refang("fxpro.com") == ("fxpro.com", False)
    assert detect("hxxpcorp.com").value == "hxxpcorp.com"


@pytest.mark.parametrize("raw, message_part", [
    ("", "Please enter"),
    ("two things", "more than one"),
    ("abc", "couldn't recognize"),
    ("1.2.3", "couldn't recognize"),
    ("a" * 30, "30 characters"),
    ("-bad-.com", "couldn't recognize"),
])
def test_rejects_with_helpful_message(raw, message_part):
    with pytest.raises(DetectionError) as error:
        detect(raw)
    assert message_part in str(error.value)
