# parse_fstec_html.py
# Извлекает уязвимости из скачанных HTML-таблиц БДУ ФСТЭК (ai.html, the_most_dangerous.html)
# и сохраняет в CSV для дальнейшего анализа.

from pathlib import Path
import re
import csv
from bs4 import BeautifulSoup

RAW_DIR = Path("data/raw")
OUT_DIR = Path("data/processed")
OUT_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT_FILE = OUT_DIR / "fstec_vulns.csv"

HTML_FILES = [
    RAW_DIR / "ai.html",
    RAW_DIR / "the_most_dangerous.html",
]


def extract_vulns_from_html(html_path: Path) -> list[dict]:
    """Извлекает строки уязвимостей из HTML-файла ФСТЭК."""
    records = []
    html = html_path.read_text(encoding="utf-8")
    soup = BeautifulSoup(html, "html.parser")

    table = soup.find("table")
    if not table:
        print(f"[!] Таблица не найдена в {html_path.name}")
        return records

    for row in table.find_all("tr"):
        cells = row.find_all("td")
        if len(cells) < 3:
            continue

        # Первая ячейка: BDU-ID
        bdu_cell = cells[0]
        bdu_link = bdu_cell.find("a")
        bdu_id = bdu_link.get_text(strip=True) if bdu_link else bdu_cell.get_text(strip=True)
        bdu_id = bdu_id.replace("BDU:", "BDU:")  # нормализация

        # Вторая ячейка: описание и ПО
        name_cell = cells[1]
        name_div = name_cell.find("div", class_="name")
        soft_div = name_cell.find("div", class_="soft")

        vuln_name = ""
        if name_div:
            h5 = name_div.find("h5")
            vuln_name = h5.get_text(strip=True) if h5 else name_div.get_text(strip=True)

        software = soft_div.get_text(" ", strip=True) if soft_div else ""

        # Третья ячейка: уровень опасности + дата
        danger_cell = cells[2]
        danger_level = ""
        date_text = ""

        # Ищем div с классом bsc-* (уровень опасности)
        for div in danger_cell.find_all("div"):
            classes = div.get("class", [])
            for cls in classes:
                if isinstance(cls, str) and cls.startswith("bsc-"):
                    danger_level = cls.replace("bsc-", "")
                    break
            if danger_level:
                break

        # Ищем дату (span или текст внутри td)
        date_span = danger_cell.find("span")
        if date_span:
            date_text = date_span.get_text(strip=True)
        else:
            # fallback: пробуем найти дату в тексте ячейки
            cell_text = danger_cell.get_text(" ", strip=True)
            m = re.search(r"(\d{2}\.\d{2}\.\d{4})", cell_text)
            if m:
                date_text = m.group(1)

        records.append({
            "source_file": html_path.name,
            "bdu_id": bdu_id,
            "vulnerability_name": vuln_name,
            "software": software,
            "danger_level": danger_level,
            "date": date_text,
        })

    return records


def main():
    all_records = []
    for html_file in HTML_FILES:
        if not html_file.exists():
            print(f"[!] Файл не найден: {html_file}")
            continue
        print(f"[+] Обрабатываю: {html_file.name}")
        recs = extract_vulns_from_html(html_file)
        all_records.extend(recs)
        print(f"    Извлечено записей: {len(recs)}")

    if not all_records:
        print("Не извлечено ни одной записи.")
        return

    # Запись CSV
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["source_file", "bdu_id", "vulnerability_name", "software", "danger_level", "date"],
        )
        writer.writeheader()
        writer.writerows(all_records)

    print(f"\n[+] Всего записей: {len(all_records)}")
    print(f"[+] Сохранено в: {OUTPUT_FILE}")

    # Краткая статистика
    danger_counts = {}
    for r in all_records:
        lvl = r["danger_level"] or "неизвестно"
        danger_counts[lvl] = danger_counts.get(lvl, 0) + 1
    print("\nРаспределение по уровням опасности:")
    for lvl, cnt in sorted(danger_counts.items()):
        print(f"  {lvl}: {cnt}")


if __name__ == "__main__":
    main()