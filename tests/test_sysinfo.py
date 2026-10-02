"""common/sysinfo.py -- CPU/RAM/อุณหภูมิ/เน็ต/ทดสอบความเร็ว (ไม่แตะเครือข่ายจริง)"""
import io

import pytest

from common import sysinfo as si


def test_cpu_percent_from_two_samples():
    samples = iter([(1000, 800), (1100, 850)])  # total +100, idle +50 -> 50%
    assert si.cpu_percent(read=lambda: next(samples), sleep=lambda s: None) == 50.0
    assert si.cpu_percent(read=lambda: None, sleep=lambda s: None) is None


def test_cpu_times_parses_proc_stat(tmp_path):
    f = tmp_path / "stat"
    f.write_text("cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 1 2 3 4\n")
    assert si._cpu_times(str(f)) == (1000, 850)


def test_memory_uses_mem_available(tmp_path):
    f = tmp_path / "meminfo"
    f.write_text("MemTotal:        4000000 kB\nMemFree:  100 kB\nMemAvailable:    3000000 kB\n")
    m = si.memory(str(f))
    assert m == dict(total=4_096_000_000, used=1_024_000_000, percent=25.0)
    assert si.memory(str(tmp_path / "missing")) is None


def test_temp_uptime_load(tmp_path):
    (tmp_path / "t").write_text("67192\n")
    (tmp_path / "u").write_text("93784.12 300000.0\n")
    (tmp_path / "l").write_text("0.33 0.30 0.21 2/194 263363\n")
    assert si.cpu_temp(str(tmp_path / "t")) == 67.2
    assert si.uptime_seconds(str(tmp_path / "u")) == 93784
    assert si.load_average(str(tmp_path / "l")) == (0.33, 0.30, 0.21)
    assert si.cpu_temp(str(tmp_path / "x")) is None


def test_default_gateway_picks_lowest_metric(tmp_path):
    f = tmp_path / "route"
    f.write_text("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
                 "wlan0\t00000000\t0100A8C0\t0003\t0\t0\t600\t00000000\n"
                 "eth0\t00000000\t0112140AC\t0003\t0\t0\t0\t00000000\n".replace("0112140AC", "0112ACAC"))
    gw = si.default_gateway(str(f))
    assert gw["iface"] == "eth0" and gw["gateway"] == "172.172.18.1"


class _Resp(io.BytesIO):
    def __init__(self, body=b"", status=200):
        super().__init__(body)
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_internet_status_online_and_offline():
    ok = si.internet_status(opener=lambda url, timeout: _Resp(status=204), resolver=lambda *a: [])
    assert ok["online"] and ok["dns_ok"] and ok["latency_ms"] is not None

    def boom(*a, **k):
        raise OSError("network unreachable")
    bad = si.internet_status(opener=boom, resolver=boom)
    assert not bad["online"] and not bad["dns_ok"] and "DNS" in bad["error"]


@pytest.fixture
def fresh_speed(monkeypatch):
    monkeypatch.setattr(si, "_last_speed", {})
    monkeypatch.setattr(si, "SPEED_DOWN_BYTES", 2_000_000)
    monkeypatch.setattr(si, "SPEED_UP_BYTES", 1_000)

    class _Sock:
        def close(self):
            pass
    monkeypatch.setattr(si, "_connect", lambda addr, timeout: _Sock())


def _fake_opener(req, timeout):
    if hasattr(req, "data") and req.data:
        return _Resp(b"ok")
    url = req if isinstance(req, str) else req.full_url
    n = int(url.rsplit("=", 1)[1])
    return _Resp(b"x" * n)


def test_speed_test_measures_and_enforces_cooldown(fresh_speed):
    clock = [1000.0]
    r = si.run_speed_test(opener=_fake_opener, now=lambda: clock[0])
    assert r["ok"] and r["down_mbps"] > 0 and r["up_mbps"] > 0 and r["ping_ms"] is not None
    assert si.last_speed_test()["down_mbps"] == r["down_mbps"]
    clock[0] += 10
    again = si.run_speed_test(opener=_fake_opener, now=lambda: clock[0])
    assert not again["ok"] and again["retry_in"] == 50, "กดซ้ำภายใน 1 นาทีไม่ได้"
    clock[0] += 60
    assert si.run_speed_test(opener=_fake_opener, now=lambda: clock[0])["ok"]


def test_speed_test_reports_failure(fresh_speed):
    def boom(*a, **k):
        raise OSError("timed out")
    r = si.run_speed_test(opener=boom)
    assert not r["ok"] and "ทดสอบไม่สำเร็จ" in r["error"]
    assert si.run_speed_test(opener=_fake_opener)["ok"], "ล้มเหลวแล้วต้องลองใหม่ได้ทันที ไม่ติด cooldown"


def test_speed_test_sends_browser_like_user_agent(fresh_speed):
    seen = []

    def spy(req, timeout):
        seen.append(req.get_header("User-agent"))
        return _fake_opener(req, timeout)
    si.run_speed_test(opener=spy)
    assert seen and all(ua and "Python" not in ua for ua in seen), "Cloudflare ตอบ 403 กับ UA ของ Python"
