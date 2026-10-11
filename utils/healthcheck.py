"""
Модуль проверки внешних зависимостей и утилит (Healthcheck).
Проверяет наличие необходимых CLI-инструментов в системе и выводит статус и инструкции по установке.
"""
import shutil
import sys

TOOLS = {
    "Recon & DNS": [
        ("dnsx", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest", "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
        ("httpx", "github.com/projectdiscovery/httpx/cmd/httpx@latest", "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"),
        ("subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
        ("amass", "github.com/owasp-amass/amass/v4/...@master", "go install -v github.com/owasp-amass/amass/v4/...@master"),
    ],
    "Crawling & URLs": [
        ("katana", "github.com/projectdiscovery/katana/cmd/katana@latest", "go install -v github.com/projectdiscovery/katana/cmd/katana@latest"),
        ("waybackurls", "github.com/tomnomnom/waybackurls@latest", "go install -v github.com/tomnomnom/waybackurls@latest"),
        ("gau", "github.com/lc/gau/v2/cmd/gau@latest", "go install -v github.com/lc/gau/v2/cmd/gau@latest"),
    ],
    "Analysis & Fingerprinting": [
        ("nmap", "Системный пакет", "sudo apt install nmap / sudo pacman -S nmap"),
        ("whatweb", "Системный пакет / Gem", "sudo apt install whatweb"),
        ("gf", "github.com/tomnomnom/gf@latest", "go install -v github.com/tomnomnom/gf@latest"),
    ],
    "Vulnerability & Fuzzing": [
        ("nuclei", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
        ("ffuf", "github.com/ffuf/ffuf/v2@latest", "go install -v github.com/ffuf/ffuf/v2@latest"),
        ("subjack", "github.com/haccer/subjack@latest", "go install -v github.com/haccer/subjack@latest"),
        ("gobuster", "Системный пакет / Go", "sudo apt install gobuster"),
    ],
    "Network Capture": [
        ("tshark", "Wireshark CLI", "sudo apt install tshark / sudo pacman -S wireshark-cli"),
    ],
}


def check_tools(verbose: bool = True) -> dict[str, bool]:
    """
    Проверяет наличие инструментов в PATH.
    Выводит форматированную таблицу статуса.
    """
    results = {}
    missing = []

    print("\n🔍 Проверка внешних утилит для ShadowScope:\n" + "=" * 55)

    for category, tool_list in TOOLS.items():
        print(f"\n📂 [{category}]")
        for name, desc, install_cmd in tool_list:
            path = shutil.which(name)
            is_present = path is not None
            results[name] = is_present

            status_mark = "✅ [OK]     " if is_present else "❌ [MISSING]"
            loc_or_hint = f"({path})" if is_present else f"→ Установка: {install_cmd}"
            print(f"  {status_mark} {name:<12} {loc_or_hint}")

            if not is_present:
                missing.append((name, install_cmd))

    print("\n" + "=" * 55)
    total = len(results)
    installed = sum(1 for v in results.values() if v)
    print(f"📊 Итог: установлено {installed}/{total} утилит.")

    if missing:
        print("\n💡 Для установки недостающих утилит выполните:")
        for name, cmd in missing:
            print(f"   • {cmd}")
        print("\n⚠️  Некоторые функции фреймворка могут быть недоступны без этих бинарников.")
    else:
        print("🎉 Все инструменты найдены и готовы к работе!")

    print()
    return results


if __name__ == "__main__":
    check_tools()
