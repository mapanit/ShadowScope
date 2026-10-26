import socket
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

from config import Config


class PortScanner:
    def __init__(self, config: Config = None, ports_range=(1, 1025)):
        # БАГ в исходнике: self.config использовался без __init__,
        # который бы его создавал -> AttributeError при первом же вызове.
        self.config = config or Config()
        # БАГ в исходнике: перебор ВСЕХ 65535 портов синхронным
        # connect_ex в один поток — это часы на один хост. По умолчанию
        # ограничиваем диапазон до well-known портов (1-1024).
        self.ports_range = ports_range

    def scan(self, target):
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror as e:
            return {"error": f"Не удалось разрешить хост {target}: {e}"}

        open_ports = []
        for port in range(*self.ports_range):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.get_timeout)
            try:
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
            finally:
                sock.close()
        return {"open_ports": open_ports}


class HTTPScanner:
    def __init__(self, config: Config = None):
        self.config = config or Config()

    def check_http(self, target):
        headers = self.config.get_http_headers
        try:
            # The URL is restricted to HTTP, so non-web schemes cannot be opened.
            urlopen(  # nosec B310
                Request(f"http://{target}", headers=headers),
                timeout=self.config.get_timeout,
            )
            return {"status": "OK", "message": "Сервер отвечает на HTTP-запросы"}
        except HTTPError as e:
            # БАГ в исходнике: код ответа искали строкой через "403" in str(e),
            # что хрупко. HTTPError.code даёт точный статус-код напрямую.
            if e.code == 403:
                return {"status": "Forbidden", "message": "Доступ запрещён (403)"}
            if e.code == 500:
                return {"status": "Server Error", "message": "Сервер вернул ошибку 500"}
            return {"status": f"HTTP {e.code}", "message": str(e)}
        except URLError as e:
            # БАГ в исходнике: если URLError не содержал "403"/"500" в
            # строковом представлении (таймаут, connection refused и т.п.),
            # функция ничего не возвращала (implicit None).
            return {"error": f"Не удалось подключиться: {e.reason}"}
        except Exception as e:
            return {"error": f"Ошибка проверки HTTP: {e}"}