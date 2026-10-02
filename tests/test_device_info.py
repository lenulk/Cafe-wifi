"""common/device_info.py -- ชื่อเครื่องจาก lease ของ dnsmasq + OS จาก User-Agent"""
import pytest

from common import device_info as di


@pytest.mark.parametrize("ua,expected", [
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15", "iPhone · iOS 17.5"),
    ("Mozilla/5.0 (iPad; CPU OS 16_6_1 like Mac OS X) AppleWebKit/605.1.15", "iPad · iPadOS 16.6.1"),
    ("Mozilla/5.0 (Linux; Android 14; SM-A546E) AppleWebKit/537.36 Chrome/126 Mobile",
     "Android 14 · SM-A546E"),
    ("Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 Chrome/126 Mobile", "Android 10"),
    ("Mozilla/5.0 (Linux; Android 13; 23028RA60L Build/TP1A.220624.014; wv) AppleWebKit/537.36",
     "Android 13 · 23028RA60L"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126", "Windows 10/11"),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15", "macOS"),
    ("Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36", "ChromeOS"),
    ("Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0", "Linux"),
    ("curl/8.5.0", None),
    ("", None),
    (None, None),
])
def test_os_from_user_agent(ua, expected):
    assert di.os_from_user_agent(ua) == expected


def test_clean_hostname_strips_dangerous_characters_and_length():
    assert di.clean_hostname("<script>alert(1)</script>") == "scriptalert1script"
    assert di.clean_hostname("Somchai's iPhone") == "SomchaisiPhone"
    assert len(di.clean_hostname("a" * 200)) == di.HOSTNAME_MAX
    assert di.clean_hostname("") is None and di.clean_hostname("'''") is None


def test_lease_hostname(tmp_path):
    f = tmp_path / "leases"
    f.write_text("1790946321 4a:8d:3d:0e:d4:a1 10.10.0.184 Redmi-Note-12-5G 01:4a:8d:3d:0e:d4:a1\n"
                 "1790942647 50:e4:e0:c4:0b:80 10.10.0.142 * 01:50:e4:e0:c4:0b:80\n"
                 "garbage\n")
    assert di.lease_hostname("4A:8D:3D:0E:D4:A1", "10.10.0.184", str(f)) == "Redmi-Note-12-5G"
    assert di.lease_hostname("4A:8D:3D:0E:D4:A1", "10.10.0.99", str(f)) is None, "IP ต้องตรงด้วย"
    assert di.lease_hostname("50:E4:E0:C4:0B:80", None, str(f)) is None, "'*' = เครื่องไม่ส่งชื่อมา"
    assert di.lease_hostname("AA:AA:AA:AA:AA:AA", None, str(tmp_path / "missing")) is None


def test_read_leases_skips_expired_and_parses_names(tmp_path):
    f = tmp_path / "leases"
    f.write_text("0 aa:bb:cc:dd:ee:01 10.10.0.101 Forever-Phone *\n"
                 "2000 aa:bb:cc:dd:ee:02 10.10.0.102 * *\n"
                 "500 aa:bb:cc:dd:ee:03 10.10.0.103 Expired *\n"
                 "junk line\n")
    got = di.read_leases(str(f), now=1000)
    assert [(l["mac"], l["ip"], l["hostname"]) for l in got] == [
        ("AA:BB:CC:DD:EE:01", "10.10.0.101", "Forever-Phone"), ("AA:BB:CC:DD:EE:02", "10.10.0.102", None)]
    assert di.read_leases(str(tmp_path / "missing")) == []


def test_dhcp_pool_size(tmp_path):
    f = tmp_path / "c.conf"
    f.write_text("# x\ninterface=eth0\ndhcp-range=10.10.0.100,10.10.0.250,255.255.255.0,4h\n")
    assert di.dhcp_pool_size(str(f)) == 151
    assert di.dhcp_pool_size(str(tmp_path / "missing")) is None
