"""Analiz sonuçlarını ağırlıklı şekilde puanlayan ve harf notu üreten modül.

Bu modül, :func:`src.analyzer.analyze_headers` çıktısını kullanarak 0-100
arası bir güvenlik skoru, buna karşılık gelen harf notu (A+ - F), kritik
sorunlar listesi ve Türkçe iyileştirme önerileri üretir.
"""

from __future__ import annotations

from typing import Any

from src.headers_config import SECURITY_HEADERS

# Tüm başlıkların ağırlıkları toplamı (yüzdelik hesaplama için bölen).
MAX_POSSIBLE_SCORE = sum(header["weight"] for header in SECURITY_HEADERS.values())

# HTTPS kullanılmıyorsa toplam skordan uygulanan ceza oranı.
HTTPS_PENALTY_RATIO = 0.20

# (alt sınır, harf notu) - büyükten küçüğe sıralı.
GRADE_THRESHOLDS: list[tuple[float, str]] = [
    (90, "A+"),
    (80, "A"),
    (70, "B"),
    (60, "C"),
    (50, "D"),
    (0, "F"),
]

# Eksik veya hatalı yapılandırılmış başlıklar için önerilen değerler.
RECOMMENDED_VALUES: dict[str, str] = {
    "Strict-Transport-Security": (
        "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    ),
    "Content-Security-Policy": "Content-Security-Policy: default-src 'self'",
    "X-Frame-Options": "X-Frame-Options: DENY",
    "X-Content-Type-Options": "X-Content-Type-Options: nosniff",
    "Referrer-Policy": "Referrer-Policy: strict-origin-when-cross-origin",
    "Permissions-Policy": "Permissions-Policy: geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Opener-Policy": "Cross-Origin-Opener-Policy: same-origin",
    "Cross-Origin-Embedder-Policy": "Cross-Origin-Embedder-Policy: require-corp",
    "Cross-Origin-Resource-Policy": "Cross-Origin-Resource-Policy: same-origin",
}

# Önerilen başlık sayısı 3'ün altında kalırsa eklenecek genel tavsiyeler.
GENERAL_RECOMMENDATIONS: list[str] = [
    "Güvenlik başlıklarının güncelliğini korumak için periyodik olarak "
    "securityheaders.com gibi araçlarla yeniden test yapılması önerilir.",
    "Content-Security-Policy politikasına 'report-uri' veya 'report-to' "
    "direktifi eklenerek ihlallerin izlenmesi sağlanabilir.",
    "Tüm alt alan adlarında (subdomain) aynı güvenlik başlıklarının "
    "uygulandığından emin olunmalıdır.",
]


def letter_grade(score: float) -> str:
    """Verilen 0-100 arası skora karşılık gelen harf notunu döndürür."""
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


def critical_issues(analysis_result: dict, headers_analysis: dict) -> list[str]:
    """Sitedeki kritik güvenlik sorunlarını Türkçe olarak listeler."""
    issues: list[str] = []

    if analysis_result.get("error"):
        issues.append(f"Bağlantı hatası: {analysis_result['error']}")

    if not analysis_result.get("https", False):
        issues.append("Site HTTPS kullanmıyor; tüm trafik düz metin olarak iletiliyor.")

    hsts = headers_analysis.get("Strict-Transport-Security", {})
    if not hsts.get("present"):
        issues.append("HSTS (Strict-Transport-Security) başlığı eksik.")

    csp = headers_analysis.get("Content-Security-Policy", {})
    if not csp.get("present"):
        issues.append("Content-Security-Policy (CSP) başlığı eksik.")
    elif "'unsafe-inline'" in csp.get("value", "").lower():
        issues.append(
            "Content-Security-Policy başlığında 'unsafe-inline' kullanılıyor; "
            "XSS riskini artırıyor."
        )

    xfo = headers_analysis.get("X-Frame-Options", {})
    if not xfo.get("present"):
        issues.append("X-Frame-Options başlığı eksik; clickjacking riskine açık.")

    return issues


def generate_recommendations(analysis_result: dict, headers_analysis: dict) -> list[str]:
    """Eksik/hatalı başlıklar için öncelik sırasına göre Türkçe öneriler üretir.

    En az 3, en çok 8 öneri döndürür.
    """
    recommendations: list[str] = []

    if not analysis_result.get("https", False):
        recommendations.append(
            "Site HTTPS üzerinden sunulmuyor. Tüm trafiği şifrelemek için "
            "siteye HTTPS yönlendirmesi eklenmelidir."
        )

    # En yüksek ağırlıklı (en etkili) başlıklar önce gelsin.
    ordered_headers = sorted(
        SECURITY_HEADERS.items(), key=lambda item: item[1]["weight"], reverse=True
    )

    for header_name, config in ordered_headers:
        if len(recommendations) >= 8:
            break

        header_result = headers_analysis.get(header_name, {})
        if header_result.get("valid"):
            continue

        recommended = RECOMMENDED_VALUES.get(header_name)
        if not recommended:
            continue

        if not header_result.get("present"):
            recommendations.append(
                f"{config['name']} başlığı eksik. Önerilen değer: {recommended}"
            )
        else:
            recommendations.append(
                f"{config['name']} başlığı hatalı yapılandırılmış. "
                f"Önerilen değer: {recommended}"
            )

    for tip in GENERAL_RECOMMENDATIONS:
        if len(recommendations) >= 3:
            break
        recommendations.append(tip)

    return recommendations[:8]


def calculate_score(analysis_result: dict) -> dict[str, Any]:
    """Analiz sonucundan toplam skor, harf notu ve önerileri hesaplar.

    Args:
        analysis_result: :func:`src.analyzer.analyze_url` çıktısına ek olarak
            ``"headers_analysis"`` anahtarında
            :func:`src.analyzer.analyze_headers` çıktısını içeren sözlük.

    Returns:
        ``{"total_score", "letter_grade", "headers_present", "headers_missing",
        "critical_issues", "recommendations"}`` anahtarlarını içeren bir sözlük.
    """
    if analysis_result.get("error"):
        return {
            "total_score": None,
            "letter_grade": "N/A",
            "headers_present": 0,
            "headers_missing": len(SECURITY_HEADERS),
            "critical_issues": [f"Bağlantı hatası: {analysis_result['error']}"],
            "recommendations": [],
        }

    headers_analysis: dict = analysis_result.get("headers_analysis", {})

    weighted_total = 0.0
    headers_present = 0
    headers_missing = 0

    for header_name, config in SECURITY_HEADERS.items():
        header_result = headers_analysis.get(header_name, {})
        weighted_total += header_result.get("score", 0.0) * config["weight"]

        if header_result.get("present"):
            headers_present += 1
        else:
            headers_missing += 1

    percentage = (weighted_total / MAX_POSSIBLE_SCORE) * 100 if MAX_POSSIBLE_SCORE else 0.0

    if not analysis_result.get("https", False):
        percentage *= 1 - HTTPS_PENALTY_RATIO

    total_score = round(max(0.0, min(percentage, 100.0)), 2)

    return {
        "total_score": total_score,
        "letter_grade": letter_grade(total_score),
        "headers_present": headers_present,
        "headers_missing": headers_missing,
        "critical_issues": critical_issues(analysis_result, headers_analysis),
        "recommendations": generate_recommendations(analysis_result, headers_analysis),
    }
