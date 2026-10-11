try:
    import whois
except ModuleNotFoundError:  # python-whois может отсутствовать в окружении
    whois = None

try:
    import dns.resolver
    import dns.exception
except ModuleNotFoundError:  # dnspython может отсутствовать в окружении
    dns = None

from urllib.parse import urlsplit


def extract_domain(target: str) -> str:
    """Возвращает hostname из домена, URL или адреса с портом."""
    target = target.strip()
    if not target:
        raise ValueError("Цель не может быть пустой")

    parsed = urlsplit(target if "://" in target else f"//{target}")
    domain = parsed.hostname
    if not domain:
        raise ValueError(f"Не удалось извлечь домен из цели: {target}")
    return domain


class WHOISScanner:
    def get_whois(self, domain):
        if whois is None:
            return {
                "domain": domain,
                "registrant": "Не доступно",
                "creation_date": "Не доступно",
                "expiration_date": "Не доступно",
                "name_servers": [],
                "error": "python-whois не установлен. Установите зависимость: pip install python-whois",
            }

        try:
            info = whois.whois(domain)
            # python-whois возвращает dict-подобный WhoisEntry — доступ
            # через .get(), а не через getattr (в оригинале был getattr
            # на dict-объекте, что не гарантированно работает для всех
            # версий библиотеки).
            return {
                "domain": domain,
                "registrant": info.get("registrant") or info.get("org") or "Не указано",
                "creation_date": info.get("creation_date", "Не доступно"),
                "expiration_date": info.get("expiration_date", "Не доступно"),
                "name_servers": info.get("name_servers", []),
            }
        except Exception as e:
            return {"error": f"Ошибка получения WHOIS: {e}"}


class DNSScanner:
    def get_dns_records(self, domain):
        if dns is None:
            return {
                "A": [],
                "MX": [],
                "TXT": [],
                "errors": {
                    "dns": "dnspython не установлен. Установите зависимость: pip install dnspython"
                },
            }

        records = {"A": [], "MX": [], "TXT": []}
        errors = {}

        # БАГ в исходнике: один общий try/except на все типы записей —
        # отсутствие, например, MX-записи (NoAnswer) роняло весь метод
        # и терялись уже полученные A-записи. Теперь каждый тип — отдельно.
        for rtype in ("A", "MX", "TXT"):
            try:
                answers = dns.resolver.resolve(domain, rtype)
                if rtype == "TXT":
                    records[rtype] = [
                        b"".join(r.strings).decode(errors="replace") for r in answers
                    ]
                else:
                    # БАГ в исходнике: A-записи добавлялись как сырые
                    # объекты dns.resolver.Answer, а не строки.
                    records[rtype] = [str(r) for r in answers]
            except dns.resolver.NoAnswer:
                records[rtype] = []
            except dns.resolver.NXDOMAIN:
                errors[rtype] = "домен не существует (NXDOMAIN)"
            except dns.exception.DNSException as e:
                errors[rtype] = str(e)

        if errors:
            records["errors"] = errors
        return records