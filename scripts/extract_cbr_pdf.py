# extract_cbr_pdf.py
# Извлекает текст из скачанных PDF отчетов ЦБ РФ и сохраняет в .txt для анализа.

from pathlib import Path
from pypdf import PdfReader

RAW_DIR = Path("data/raw")
OUT_DIR = Path("data/processed")
OUT_DIR.mkdir(parents=True, exist_ok=True)

pdf_files = sorted(RAW_DIR.glob("cbr_*.pdf"))

for pdf_path in pdf_files:
    print(f"Обрабатываю: {pdf_path.name}")
    try:
        reader = PdfReader(str(pdf_path))
        text_parts = []
        for i, page in enumerate(reader.pages, start=1):
            try:
                page_text = page.extract_text() or ""
            except Exception as e:
                page_text = f"[Ошибка извлечения страницы {i}: {e}]\n"
            text_parts.append(f"\n=== Страница {i} ===\n{page_text}")
        
        full_text = "\n".join(text_parts)
        out_path = OUT_DIR / (pdf_path.stem + ".txt")
        out_path.write_text(full_text, encoding="utf-8")
        print(f"  Сохранено: {out_path} ({len(full_text)} символов)")
    except Exception as e:
        print(f"  Ошибка при обработке {pdf_path.name}: {e}")

print("\nГотово. Текстовые файлы лежат в data/processed/")