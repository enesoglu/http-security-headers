"""Analiz sonuçlarını JSON, CSV ve Markdown formatlarında dışa aktaran modül."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path


def export_json(results: list[dict], output_path: str) -> str:
    """Analiz sonuçlarını zaman damgalı bir JSON dosyasına yazar.

    Args:
        results: Her biri bir sitenin analiz/skor sonucunu içeren sözlük listesi.
        output_path: Raporun yazılacağı klasör (yoksa oluşturulur).

    Returns:
        Oluşturulan JSON dosyasının yolu.
    """
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_path = output_dir / f"analysis_{timestamp}.json"

    payload = {
        "generated_at": datetime.now().isoformat(),
        "site_count": len(results),
        "results": results,
    }

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    return str(file_path)
