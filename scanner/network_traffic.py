import shutil
import subprocess

try:
    import pyshark
    _PYSHARK_AVAILABLE = True
except ImportError:
    _PYSHARK_AVAILABLE = False


def _parse_open_ports(nmap_output: str):
    """Вытащить номера открытых TCP-портов из текстового вывода nmap."""
    import re
    ports = []
    for line in nmap_output.splitlines():
        m = re.match(r"^(\d+)/tcp\s+open\b", line)
        if m:
            ports.append(int(m.group(1)))
    return ports


class NetworkTrafficScanner:
    def __init__(self, rate_limit=10):
        self.rate_limit = rate_limit

    def analyze_with_nmap(self, target):
        if shutil.which("nmap") is None:
            return {"error": "nmap не установлен"}

        # вытаскиваем порт из target, если он передан явно (127.0.0.1:5012)
        host = target
        port = None
        if not target.startswith(("http://", "https://")) and ":" in target:
            host, port_str = target.rsplit(":", 1)
            if port_str.isdigit():
                port = int(port_str)

        # http-enum имеет смысл только для HTTP-портов
        # если порт известен — сканируем только его
        port_arg = str(port) if port else "80,443,8000,8080,5012"

        try:
            result = subprocess.run(
                ["nmap", "-Pn", "-sV",
                 "--scan-delay", f"{1 / self.rate_limit:.3f}s",
                 "--script=http-enum",
                 "-p", port_arg,
                 host],
                capture_output=True, text=True, timeout=120, check=True,
            )
            return {
                "raw_output": result.stdout.strip(),
                "open_ports": _parse_open_ports(result.stdout),
                "vulnerabilities": [
                    line for line in result.stdout.splitlines()
                    if "VULNERABLE" in line
                ],
            }
        except subprocess.CalledProcessError as e:
            return {"error": f"Nmap http-enum scan failed: {e.stderr.strip()}"}
        except subprocess.TimeoutExpired:
            return {"error": "Nmap http-enum: превышен таймаут"}
        except Exception as e:
            return {"error": f"Nmap http-enum scan failed: {e}"}


class TrafficCaptureScanner:
    """
    Обёртка над pyshark (Python-биндинг к tshark).
    Требует tshark в PATH и прав на захват пакетов.
    """

    def __init__(self, interface="eth0", packet_count=50, timeout=20):
        self.interface = interface
        self.packet_count = packet_count
        self.timeout = timeout

    def capture(self):
        if not _PYSHARK_AVAILABLE:
            return {"error": "pyshark не установлен"}
        if shutil.which("tshark") is None:
            return {"error": "tshark не установлен (нужен для pyshark)"}

        capture = None
        try:
            capture = pyshark.LiveCapture(interface=self.interface)
            capture.sniff(timeout=self.timeout, packet_count=self.packet_count)

            summary = []
            for packet in capture:
                try:
                    summary.append({
                        "protocol": packet.highest_layer,
                        "src": packet.ip.src if hasattr(packet, "ip") else "?",
                        "dst": packet.ip.dst if hasattr(packet, "ip") else "?",
                        "length": packet.length,
                    })
                except AttributeError:
                    continue
            return {"packets": summary, "count": len(summary)}
        except Exception as e:
            return {"error": f"Traffic capture failed: {e}"}
        finally:
            if capture is not None:
                capture.close()