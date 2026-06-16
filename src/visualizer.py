"""Analiz sonuçlarını PNG grafiklere dönüştüren görselleştirme modülü."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt

from src.headers_config import SECURITY_HEADERS

# Türkçe karakterlerin grafiklerde doğru görüntülenmesi için.
plt.rcParams["font.family"] = "DejaVu Sans"

DEFAULT_OUTPUT_DIR = "output/charts"
DPI = 150

# Harf notuna göre çubuk/pasta grafik renkleri.
GRADE_COLORS = {
    "A+": "#1b5e20",
    "A": "#43a047",
    "B": "#fdd835",
    "C": "#fb8c00",
    "D": "#e53935",
    "F": "#b71c1c",
    "N/A": "#9e9e9e",
}

GRADE_ORDER = ["A+", "A", "B", "C", "D", "F"]


def _resolve_timestamp(timestamp: str | None) -> str:
    """Verilmemişse şu anki zamana göre bir zaman damgası üretir."""
    return timestamp or datetime.now().strftime("%Y%m%d_%H%M%S")


def _ensure_output_dir(output_path: str) -> Path:
    """Çıktı klasörünü oluşturur (yoksa) ve Path nesnesini döndürür."""
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def _short_label(url: str) -> str:
    """Bir URL'den okunabilir kısa bir site etiketi üretir."""
    label = url.replace("https://", "").replace("http://", "").rstrip("/")
    if label.startswith("www."):
        label = label[4:]
    return label


def plot_score_comparison(
    results: list[dict], output_path: str, timestamp: str | None = None
) -> str:
    """Sitelerin güvenlik skorlarını yüksekten düşüğe sıralı yatay bar chart olarak çizer.

    Args:
        results: Her biri bir sitenin analiz/skor sonucunu içeren sözlük listesi.
        output_path: PNG dosyasının kaydedileceği klasör (yoksa oluşturulur).
        timestamp: Dosya adında kullanılacak zaman damgası (verilmezse otomatik üretilir).

    Returns:
        Oluşturulan PNG dosyasının yolu.
    """
    output_dir = _ensure_output_dir(output_path)
    file_path = output_dir / f"scores_{_resolve_timestamp(timestamp)}.png"

    rows = [
        {
            "label": _short_label(r["url"]),
            "score": r["total_score"] if not r.get("error") else 0.0,
            "grade": r["letter_grade"],
        }
        for r in results
    ]
    rows.sort(key=lambda row: row["score"], reverse=True)

    labels = [row["label"] for row in rows]
    scores = [row["score"] for row in rows]
    colors = [GRADE_COLORS.get(row["grade"], "#9e9e9e") for row in rows]

    fig_height = max(4, 0.5 * len(labels) + 1.5)
    fig, ax = plt.subplots(figsize=(10, fig_height))

    y_positions = range(len(labels))
    ax.barh(y_positions, scores, color=colors)
    ax.set_yticks(list(y_positions))
    ax.set_yticklabels(labels)
    ax.invert_yaxis()
    ax.set_xlim(0, 100)
    ax.set_xlabel("Güvenlik Skoru")
    ax.set_title("Türkiye'deki Popüler Sitelerin Güvenlik Başlıkları Skoru")

    for y, row in zip(y_positions, rows):
        ax.text(row["score"] + 1, y, f"{row['score']:.1f} ({row['grade']})", va="center")

    fig.tight_layout()
    fig.savefig(file_path, dpi=DPI)
    plt.close(fig)

    return str(file_path)


def plot_grade_distribution(
    results: list[dict], output_path: str, timestamp: str | None = None
) -> str:
    """Harf notu dağılımını (A+/A/B/C/D/F) pasta grafik olarak çizer.

    Args:
        results: Her biri bir sitenin analiz/skor sonucunu içeren sözlük listesi.
        output_path: PNG dosyasının kaydedileceği klasör (yoksa oluşturulur).
        timestamp: Dosya adında kullanılacak zaman damgası (verilmezse otomatik üretilir).

    Returns:
        Oluşturulan PNG dosyasının yolu.
    """
    output_dir = _ensure_output_dir(output_path)
    file_path = output_dir / f"grades_{_resolve_timestamp(timestamp)}.png"

    counts = {grade: 0 for grade in GRADE_ORDER}
    for r in results:
        if r.get("error"):
            continue
        counts[r["letter_grade"]] = counts.get(r["letter_grade"], 0) + 1

    labels = [grade for grade in GRADE_ORDER if counts[grade] > 0]
    sizes = [counts[grade] for grade in labels]
    colors = [GRADE_COLORS[grade] for grade in labels]

    if not sizes:
        labels, sizes, colors = ["Veri Yok"], [1], ["#9e9e9e"]

    fig, ax = plt.subplots(figsize=(6, 6))
    ax.pie(sizes, labels=labels, colors=colors, autopct="%1.0f%%", startangle=90)
    ax.set_title("Not Dağılımı")

    fig.tight_layout()
    fig.savefig(file_path, dpi=DPI)
    plt.close(fig)

    return str(file_path)


def plot_header_coverage(
    results: list[dict], output_path: str, timestamp: str | None = None
) -> str:
    """Her güvenlik başlığının sitelerde bulunma yüzdesini bar chart olarak çizer.

    %50'nin altındaki kullanım oranları kırmızı, üstündekiler yeşil ile gösterilir.

    Args:
        results: Her biri bir sitenin analiz/skor sonucunu içeren sözlük listesi.
        output_path: PNG dosyasının kaydedileceği klasör (yoksa oluşturulur).
        timestamp: Dosya adında kullanılacak zaman damgası (verilmezse otomatik üretilir).

    Returns:
        Oluşturulan PNG dosyasının yolu.
    """
    output_dir = _ensure_output_dir(output_path)
    file_path = output_dir / f"coverage_{_resolve_timestamp(timestamp)}.png"

    valid_results = [r for r in results if not r.get("error")]
    total = len(valid_results)

    header_names = list(SECURITY_HEADERS.keys())
    percentages = []
    for header_name in header_names:
        if total == 0:
            percentages.append(0.0)
            continue
        present_count = sum(
            1
            for r in valid_results
            if r["headers_analysis"].get(header_name, {}).get("present")
        )
        percentages.append(present_count / total * 100)

    colors = ["#43a047" if p >= 50 else "#e53935" for p in percentages]

    fig, ax = plt.subplots(figsize=(10, 6))
    y_positions = range(len(header_names))
    ax.barh(y_positions, percentages, color=colors)
    ax.set_yticks(list(y_positions))
    ax.set_yticklabels(header_names)
    ax.invert_yaxis()
    ax.set_xlim(0, 100)
    ax.set_xlabel("Kullanım Oranı (%)")
    ax.set_title("Güvenlik Başlıklarının Kullanım Oranı (%)")

    for y, p in zip(y_positions, percentages):
        ax.text(p + 1, y, f"{p:.0f}%", va="center")

    fig.tight_layout()
    fig.savefig(file_path, dpi=DPI)
    plt.close(fig)

    return str(file_path)


def generate_all_charts(results: list[dict], timestamp: str) -> list[str]:
    """Skor karşılaştırma, not dağılımı ve başlık kapsama grafiklerini tek seferde üretir.

    Args:
        results: Her biri bir sitenin analiz/skor sonucunu içeren sözlük listesi.
        timestamp: Üretilecek tüm dosya adlarında kullanılacak ortak zaman damgası.

    Returns:
        Oluşturulan PNG dosyalarının yollarını içeren bir liste.
    """
    return [
        plot_score_comparison(results, DEFAULT_OUTPUT_DIR, timestamp),
        plot_grade_distribution(results, DEFAULT_OUTPUT_DIR, timestamp),
        plot_header_coverage(results, DEFAULT_OUTPUT_DIR, timestamp),
    ]
