"""Analiz sonuçlarını JSON, CSV ve Markdown formatlarında dışa aktaran modül."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pandas as pd
from tabulate import tabulate

from src.headers_config import SECURITY_HEADERS

# Harf notlarının "Özet İstatistikler" bölümünde gösterim sırası.
GRADE_ORDER = ["A+", "A", "B", "C", "D", "F"]

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


def _format_header_value(value: str) -> str:
    """Markdown tablosunda satırı bozmaması için başlık değerini kısaltır/temizler."""
    if not value:
        return "-"
    cleaned = value.replace("|", "\\|").replace("\n", " ")
    if len(cleaned) > 80:
        cleaned = cleaned[:77] + "..."
    return f"`{cleaned}`"


def _header_status_label(header_result: dict) -> str:
    """Bir başlığın durumunu Markdown için kısa bir etikete çevirir."""
    if header_result["valid"]:
        return "✅ Geçerli"
    if header_result["present"]:
        return "⚠️ Hatalı"
    return "❌ Eksik"


def export_markdown(results: list[dict], output_path: str) -> str:
    """Analiz sonuçlarını akademik formatta bir Markdown raporuna yazar.

    Rapor; özet istatistikler, karşılaştırmalı tablo, her site için detaylı
    analiz ve genel bir değerlendirme bölümü içerir.

    Args:
        results: Her biri bir sitenin analiz/skor sonucunu içeren sözlük listesi.
        output_path: Raporun yazılacağı klasör (yoksa oluşturulur).

    Returns:
        Oluşturulan Markdown dosyasının yolu.
    """
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_path = output_dir / f"analysis_{timestamp}.md"

    now = datetime.now()
    valid_results = [r for r in results if not r.get("error")]

    lines: list[str] = []

    # Başlık
    lines.append("# HTTP Güvenlik Başlıkları Analiz Raporu")
    lines.append("")
    lines.append(f"**Analiz Tarihi:** {now.strftime('%d.%m.%Y %H:%M:%S')}")
    lines.append("")

    # Özet istatistikler
    lines.append("## Özet İstatistikler")
    lines.append("")
    lines.append(f"- **Analiz edilen site sayısı:** {len(results)}")
    lines.append(f"- **Erişilebilen site sayısı:** {len(valid_results)}")

    if valid_results:
        scores = [r["total_score"] for r in valid_results]
        avg_score = sum(scores) / len(scores)
        best = max(valid_results, key=lambda r: r["total_score"])
        worst = min(valid_results, key=lambda r: r["total_score"])

        lines.append(f"- **Ortalama skor:** {avg_score:.2f} / 100")
        lines.append(
            f"- **En yüksek skor:** {best['url']} "
            f"({best['total_score']:.2f}, {best['letter_grade']})"
        )
        lines.append(
            f"- **En düşük skor:** {worst['url']} "
            f"({worst['total_score']:.2f}, {worst['letter_grade']})"
        )

        grade_counts: dict[str, int] = {}
        for r in valid_results:
            grade_counts[r["letter_grade"]] = grade_counts.get(r["letter_grade"], 0) + 1

        distribution = ", ".join(
            f"{grade}: {grade_counts[grade]}" for grade in GRADE_ORDER if grade in grade_counts
        )
        lines.append(f"- **Not dağılımı:** {distribution}")
    else:
        lines.append("- Analiz edilen sitelerin hiçbirine erişilemedi.")

    lines.append("")

    # Karşılaştırmalı tablo
    lines.append("## Karşılaştırmalı Tablo")
    lines.append("")

    table_rows = []
    has_4xx = False
    for r in results:
        if r.get("error"):
            table_rows.append([r["url"], "-", "N/A", "-", "-", "-"])
        else:
            url_cell = r["url"]
            if r.get("status_code") and r["status_code"] >= 400:
                url_cell += f" ⚠ HTTP {r['status_code']}"
                has_4xx = True
            table_rows.append(
                [
                    url_cell,
                    f"{r['total_score']:.2f}",
                    r["letter_grade"],
                    r["headers_present"],
                    r["headers_missing"],
                    len(r["critical_issues"]),
                ]
            )

    lines.append(
        tabulate(
            table_rows,
            headers=["Site", "Skor", "Not", "Mevcut Başlık", "Eksik Başlık", "Kritik Sorun"],
            tablefmt="github",
        )
    )
    if has_4xx:
        lines.append("")
        lines.append(
            "> **⚠ Uyarı:** `⚠ HTTP 4xx` etiketli siteler bot-engelleme veya WAF "
            "katmanından 4xx yanıtı döndürmüştür. Analiz edilen başlıklar gerçek "
            "sitenin normal 200 yanıtındaki başlıklardan farklı olabilir; "
            "sonuçlar bu siteler için temsili olmayabilir."
        )
    lines.append("")

    # Detaylı analiz
    lines.append("## Detaylı Analiz")
    lines.append("")

    for r in results:
        lines.append(f"### {r['url']}")
        lines.append("")

        if r.get("error"):
            lines.append(f"**Hata:** {r['error']}")
            lines.append("")
            continue

        lines.append(f"- **Son URL:** {r['final_url']}")
        lines.append(f"- **Durum Kodu:** {r['status_code']}")
        lines.append(f"- **HTTPS:** {'Evet' if r['https'] else 'Hayır'}")
        lines.append(f"- **Skor:** {r['total_score']:.2f} / 100 ({r['letter_grade']})")
        lines.append(f"- **Yanıt Süresi:** {r['response_time_ms']} ms")
        lines.append("")

        if r.get("status_code") and r["status_code"] >= 400:
            lines.append(
                f"> **⚠ HTTP {r['status_code']} Uyarısı:** Bu site bot-engelleme veya WAF "
                "katmanından hata yanıtı döndürmüştür. Aşağıdaki başlıklar gerçek "
                "sitenin normal yanıtını yansıtmıyor olabilir."
            )
            lines.append("")

        lines.append("| Başlık | Durum | Değer | Sorunlar |")
        lines.append("|---|---|---|---|")
        for header_name in SECURITY_HEADERS:
            header_result = r["headers_analysis"].get(header_name, {})
            status = _header_status_label(header_result)
            value = _format_header_value(header_result.get("value", ""))
            issues = header_result.get("issues", [])
            issues_cell = "; ".join(issues) if issues else "-"
            if len(issues_cell) > 120:
                issues_cell = issues_cell[:117] + "..."
            lines.append(f"| {header_name} | {status} | {value} | {issues_cell} |")
        lines.append("")

        if r["critical_issues"]:
            lines.append("**Kritik Sorunlar:**")
            for issue in r["critical_issues"]:
                lines.append(f"- {issue}")
            lines.append("")

        if r["recommendations"]:
            lines.append("**Öneriler:**")
            for rec in r["recommendations"]:
                lines.append(f"- {rec}")
            lines.append("")

    # Sonuç ve genel değerlendirme
    lines.append("## Sonuç ve Genel Değerlendirme")
    lines.append("")

    if valid_results:
        header_coverage = {}
        for header_name in SECURITY_HEADERS:
            present_count = sum(
                1
                for r in valid_results
                if r["headers_analysis"].get(header_name, {}).get("present")
            )
            header_coverage[header_name] = present_count

        most_common = max(header_coverage.items(), key=lambda item: item[1])
        least_common = min(header_coverage.items(), key=lambda item: item[1])

        lines.append(
            f"Bu raporda toplam {len(results)} site analiz edilmiş, bunlardan "
            f"{len(valid_results)} sitesine başarıyla erişilmiştir. Ortalama "
            f"güvenlik skoru **{avg_score:.2f}/100** olarak hesaplanmıştır."
        )
        lines.append("")
        lines.append(
            f"En yaygın uygulanan güvenlik başlığı **{most_common[0]}** "
            f"({most_common[1]}/{len(valid_results)} sitede mevcut), en az "
            f"uygulanan başlık ise **{least_common[0]}** "
            f"({least_common[1]}/{len(valid_results)} sitede mevcut) olarak "
            "tespit edilmiştir."
        )
        lines.append("")
        lines.append(
            "Genel olarak, analiz edilen sitelerin güvenlik başlığı "
            "yapılandırmasında geliştirmeye açık alanlar bulunmaktadır. "
            "Yukarıda her site için listelenen önerilerin uygulanması; "
            "Cross-Site Scripting (XSS), clickjacking, MIME sniffing ve "
            "ortadaki adam (MITM) gibi yaygın saldırı türlerine karşı "
            "direnci önemli ölçüde artıracaktır."
        )
    else:
        lines.append("Hiçbir siteye erişilemediği için genel bir değerlendirme yapılamamıştır.")

    lines.append("")

    file_path.write_text("\n".join(lines), encoding="utf-8")

    return str(file_path)
