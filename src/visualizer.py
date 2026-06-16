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


def plot_header_matrix(
    results: list[dict], output_path: str, timestamp: str | None = None
) -> str:
    """Her sitenin hangi güvenlik başlıklarına sahip olduğunu ısı haritası olarak çizer.

    Hücreler: yeşil = geçerli, sarı = mevcut ama hatalı, kırmızı = eksik, gri = erişilemedi.

    Args:
        results: Her biri bir sitenin analiz/skor sonucunu içeren sözlük listesi.
        output_path: PNG dosyasının kaydedileceği klasör (yoksa oluşturulur).
        timestamp: Dosya adında kullanılacak zaman damgası (verilmezse otomatik üretilir).

    Returns:
        Oluşturulan PNG dosyasının yolu.
    """
    from matplotlib.patches import Patch

    output_dir = _ensure_output_dir(output_path)
    file_path = output_dir / f"matrix_{_resolve_timestamp(timestamp)}.png"

    header_names = list(SECURITY_HEADERS.keys())
    short_headers = ["HSTS", "CSP", "XFO", "XCTO", "Ref-P", "Perm-P", "XSS-P", "COOP", "COEP", "CORP"]
    site_labels = [_short_label(r["url"]) for r in results]

    n_sites = len(results)
    n_headers = len(header_names)

    cell_colors = {"valid": "#43a047", "partial": "#fdd835", "missing": "#e53935", "na": "#9e9e9e"}
    cell_texts = {"valid": "✓", "partial": "~", "missing": "✗", "na": "-"}
    text_colors = {"valid": "white", "partial": "#333333", "missing": "white", "na": "white"}

    fig_height = max(4, 0.55 * n_sites + 2)
    fig, ax = plt.subplots(figsize=(14, fig_height))

    for i, result in enumerate(results):
        for j, header_name in enumerate(header_names):
            if result.get("error"):
                state = "na"
            else:
                hr = result["headers_analysis"].get(header_name, {})
                if hr.get("valid"):
                    state = "valid"
                elif hr.get("present"):
                    state = "partial"
                else:
                    state = "missing"

            rect = plt.Rectangle(
                [j, i], 1, 1,
                facecolor=cell_colors[state],
                edgecolor="white",
                linewidth=1.5,
            )
            ax.add_patch(rect)
            ax.text(
                j + 0.5, i + 0.5, cell_texts[state],
                ha="center", va="center", fontsize=11,
                color=text_colors[state], fontweight="bold",
            )

    ax.set_xlim(0, n_headers)
    ax.set_ylim(0, n_sites)
    ax.set_xticks([j + 0.5 for j in range(n_headers)])
    ax.set_xticklabels(short_headers, rotation=45, ha="right", fontsize=9)
    ax.set_yticks([i + 0.5 for i in range(n_sites)])
    ax.set_yticklabels(site_labels, fontsize=9)
    ax.invert_yaxis()
    ax.set_title("Güvenlik Başlığı Varlık Matrisi", pad=12)

    legend_elements = [
        Patch(facecolor=cell_colors["valid"], label="Geçerli (✓)"),
        Patch(facecolor=cell_colors["partial"], label="Mevcut ama hatalı (~)"),
        Patch(facecolor=cell_colors["missing"], label="Eksik (✗)"),
        Patch(facecolor=cell_colors["na"], label="Erişilemedi (-)"),
    ]
    ax.legend(handles=legend_elements, loc="upper right", bbox_to_anchor=(1.22, 1), fontsize=8)

    fig.tight_layout()
    fig.savefig(file_path, dpi=DPI, bbox_inches="tight")
    plt.close(fig)

    return str(file_path)


def generate_all_charts(results: list[dict], timestamp: str) -> list[str]:
    """Skor karşılaştırma, not dağılımı, başlık kapsama ve varlık matrisi grafiklerini üretir.

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
        plot_header_matrix(results, DEFAULT_OUTPUT_DIR, timestamp),
    ]
