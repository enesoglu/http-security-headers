"""Analiz sonuçlarını JSON, CSV ve Markdown formatlarında dışa aktaran modül."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pandas as pd

CSV_COLUMNS = [
    "url",
    "final_url",
    "status_code",
    "https",
    "total_score",
    "letter_grade",
    "hsts_present",
    "csp_present",
    "xfo_present",
    "xcto_present",
    "referrer_policy_present",
    "permissions_policy_present",
    "critical_issues_count",
    "response_time_ms",
]


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


def export_csv(results: list[dict], output_path: str) -> str:
    """Analiz sonuçlarını zaman damgalı bir CSV dosyasına yazar.

    Dosya, Excel'de Türkçe karakterlerin doğru görünmesi için UTF-8 BOM
    (``utf-8-sig``) ile kaydedilir.

    Args:
        results: Her biri bir sitenin analiz/skor sonucunu içeren sözlük listesi.
        output_path: Raporun yazılacağı klasör (yoksa oluşturulur).

    Returns:
        Oluşturulan CSV dosyasının yolu.
    """
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_path = output_dir / f"analysis_{timestamp}.csv"

    rows = []
    for result in results:
        headers_analysis = result.get("headers_analysis", {})
        rows.append(
            {
                "url": result.get("url"),
                "final_url": result.get("final_url"),
                "status_code": result.get("status_code"),
                "https": result.get("https"),
                "total_score": result.get("total_score"),
                "letter_grade": result.get("letter_grade"),
                "hsts_present": headers_analysis.get("Strict-Transport-Security", {}).get(
                    "present", False
                ),
                "csp_present": headers_analysis.get("Content-Security-Policy", {}).get(
                    "present", False
                ),
                "xfo_present": headers_analysis.get("X-Frame-Options", {}).get(
                    "present", False
                ),
                "xcto_present": headers_analysis.get("X-Content-Type-Options", {}).get(
                    "present", False
                ),
                "referrer_policy_present": headers_analysis.get("Referrer-Policy", {}).get(
                    "present", False
                ),
                "permissions_policy_present": headers_analysis.get(
                    "Permissions-Policy", {}
                ).get("present", False),
                "critical_issues_count": len(result.get("critical_issues", [])),
                "response_time_ms": result.get("response_time_ms"),
            }
        )

    df = pd.DataFrame(rows, columns=CSV_COLUMNS)
    df.to_csv(file_path, index=False, encoding="utf-8-sig")

    return str(file_path)
