"""HTTP Güvenlik Başlıkları Analiz Aracı - komut satırı arayüzü.

Kullanım örnekleri::

    python main.py --url https://example.com
    python main.py --file data/turkish_sites.txt
    python main.py --file data/turkish_sites.txt --output all
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from src.analyzer import DEFAULT_TIMEOUT, analyze_headers, analyze_url
from src.reporter import export_csv, export_json, export_markdown
from src.scorer import calculate_score
from src.visualizer import generate_all_charts

REPORTS_DIR = "output/reports"

GRADE_STYLES = {
    "A+": "bold green",
    "A": "green",
    "B": "yellow",
    "C": "yellow",
    "D": "red",
    "F": "bold red",
}

console = Console()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Komut satırı argümanlarını ayrıştırır."""
    parser = argparse.ArgumentParser(
        description="HTTP güvenlik başlıklarını analiz eder ve A+ ile F arasında not verir."
    )

    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--url", help="Analiz edilecek tek bir URL")
    target.add_argument("--file", help="Her satırda bir URL içeren dosya yolu")

    parser.add_argument(
        "--output",
        choices=["terminal", "json", "csv", "markdown", "all"],
        default="terminal",
        help="Çıktı formatı (varsayılan: terminal)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"İstek zaman aşımı, saniye (varsayılan: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Her site için detaylı başlık analizini göster",
    )

    return parser.parse_args(argv)


def load_urls(args: argparse.Namespace) -> list[str]:
    """--url veya --file argümanından analiz edilecek URL listesini döndürür."""
    if args.url:
        return [args.url]

    file_path = Path(args.file)
    if not file_path.is_file():
        raise FileNotFoundError(f"'{args.file}' adında bir dosya bulunamadı.")

    urls = [
        line.strip()
        for line in file_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    if not urls:
        raise ValueError(f"'{args.file}' dosyasında analiz edilecek URL bulunamadı.")

    return urls


def analyze_single(url: str, timeout: int) -> dict:
    """Bir URL'i analiz eder, başlıkları değerlendirir ve skorla birleştirir."""
    result = analyze_url(url, timeout=timeout)
    result["headers_analysis"] = analyze_headers(result["headers"])
    result.update(calculate_score(result))
    return result


def print_verbose_details(result: dict) -> None:
    """Tek bir site için detaylı başlık analizini terminale yazdırır."""
    console.print(f"\n[bold cyan]{result['url']}[/bold cyan]")

    if result["error"]:
        console.print(f"  [red]{result['error']}[/red]")
        return

    console.print(f"  Durum kodu     : {result['status_code']}")
    console.print(f"  Son URL        : {result['final_url']}")
    console.print(f"  HTTPS          : {'Evet' if result['https'] else 'Hayır'}")
    console.print(f"  Yanıt süresi   : {result['response_time_ms']} ms")
    console.print(f"  Yönlendirildi  : {'Evet' if result['redirected'] else 'Hayır'}")

    detail_table = Table(show_header=True, header_style="bold")
    detail_table.add_column("Başlık")
    detail_table.add_column("Durum", justify="center")
    detail_table.add_column("Değer / Sorunlar")

    for header_name, header_result in result["headers_analysis"].items():
        if header_result["valid"]:
            status = "[green]Geçerli[/green]"
        elif header_result["present"]:
            status = "[yellow]Hatalı[/yellow]"
        else:
            status = "[red]Eksik[/red]"

        details = header_result["value"] or "-"
        if header_result["issues"]:
            details += "\n" + "\n".join(f"• {issue}" for issue in header_result["issues"])

        detail_table.add_row(header_name, status, details)

    console.print(detail_table)

    if result["critical_issues"]:
        console.print("  [bold red]Kritik Sorunlar:[/bold red]")
        for issue in result["critical_issues"]:
            console.print(f"    - {issue}")

    if result["recommendations"]:
        console.print("  [bold]Öneriler:[/bold]")
        for rec in result["recommendations"]:
            console.print(f"    - {rec}")


def print_summary_table(results: list[dict]) -> None:
    """Tüm siteler için renkli özet karşılaştırma tablosunu yazdırır."""
    table = Table(title="HTTP Güvenlik Başlıkları Analiz Özeti")
    table.add_column("Site", style="cyan", overflow="fold")
    table.add_column("Skor", justify="right")
    table.add_column("Not", justify="center")
    table.add_column("Eksik Başlıklar", justify="right")
    table.add_column("Kritik Sorunlar", justify="right")

    for result in results:
        if result["error"]:
            table.add_row(
                result["url"],
                "-",
                "[dim]N/A[/dim]",
                "-",
                f"[red]{result['error']}[/red]",
            )
            continue

        grade = result["letter_grade"]
        style = GRADE_STYLES.get(grade, "white")

        table.add_row(
            result["url"],
            f"{result['total_score']:.2f}",
            f"[{style}]{grade}[/{style}]",
            str(result["headers_missing"]),
            str(len(result["critical_issues"])),
        )

    console.print(table)


def export_results(results: list[dict], output: str, timestamp: str) -> None:
    """Sonuçları seçilen formatlarda dışa aktarır (rapor dosyaları ve grafikler)."""
    formats = ["json", "csv", "markdown"] if output == "all" else [output]

    if "json" in formats:
        path = export_json(results, REPORTS_DIR)
        console.print(f"[green]JSON raporu kaydedildi:[/green] {path}")

    if "csv" in formats:
        path = export_csv(results, REPORTS_DIR)
        console.print(f"[green]CSV raporu kaydedildi:[/green] {path}")

    if "markdown" in formats:
        path = export_markdown(results, REPORTS_DIR)
        console.print(f"[green]Markdown raporu kaydedildi:[/green] {path}")

    if output == "all":
        chart_paths = generate_all_charts(results, timestamp)
        for chart_path in chart_paths:
            console.print(f"[green]Grafik kaydedildi:[/green] {chart_path}")


def main(argv: list[str] | None = None) -> int:
    """Komut satırı aracının giriş noktası."""
    args = parse_args(argv)

    try:
        urls = load_urls(args)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[bold red]Hata:[/bold red] {exc}")
        return 1

    results: list[dict] = []

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Analiz ediliyor...", total=len(urls))

            for url in urls:
                progress.update(task, description=f"Analiz ediliyor: {url}")
                results.append(analyze_single(url, args.timeout))
                progress.advance(task)

        if args.verbose:
            for result in results:
                print_verbose_details(result)

        print_summary_table(results)

        valid_scores = [r["total_score"] for r in results if not r["error"]]
        if valid_scores:
            avg_score = sum(valid_scores) / len(valid_scores)
            console.print(
                f"\n[bold]Tüm analizler tamamlandı:[/bold] {len(results)} site, "
                f"ortalama skor: {avg_score:.2f}"
            )
        else:
            console.print(
                f"\n[bold]Tüm analizler tamamlandı:[/bold] {len(results)} site, "
                "ortalama skor hesaplanamadı (hiçbir siteye ulaşılamadı)."
            )

        if args.output != "terminal":
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            export_results(results, args.output, timestamp)

        return 0

    except KeyboardInterrupt:
        console.print("\n[yellow]İşlem kullanıcı tarafından durduruldu.[/yellow]")
        return 130
    except Exception as exc:  # pragma: no cover - beklenmeyen hatalar için son çare
        console.print(f"\n[bold red]Beklenmeyen bir hata oluştu:[/bold red] {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
