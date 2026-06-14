"""Başlık doğrulayıcıları ve skor hesaplama için birim testleri.

Bu testler tamamen yerel veriler üzerinde çalışır; gerçek bir HTTP isteği
göndermez.
"""

from __future__ import annotations

from src.analyzer import analyze_headers
from src.headers_config import validate_csp, validate_hsts, validate_xfo
from src.scorer import calculate_score, letter_grade


def test_validate_hsts_valid():
    result = validate_hsts("max-age=31536000; includeSubDomains; preload")

    assert result["valid"] is True
    assert result["score"] == 1.0
    assert result["issues"] == []


def test_validate_hsts_short_maxage():
    result = validate_hsts("max-age=3600")

    assert result["valid"] is False
    assert result["score"] < 0.5
    assert any("1 yıl" in issue for issue in result["issues"])


def test_validate_csp_unsafe_inline():
    result = validate_csp("default-src 'self'; script-src 'self' 'unsafe-inline'")

    assert result["score"] < 0.7
    assert any("unsafe-inline" in issue for issue in result["issues"])


def test_validate_xfo_deny():
    result = validate_xfo("DENY")

    assert result["valid"] is True
    assert result["score"] == 1.0
    assert result["issues"] == []


def test_score_calculation_perfect():
    headers = {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
        "X-XSS-Protection": "1; mode=block",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Embedder-Policy": "require-corp",
        "Cross-Origin-Resource-Policy": "same-origin",
    }

    analysis_result = {
        "https": True,
        "error": None,
        "headers_analysis": analyze_headers(headers),
    }

    result = calculate_score(analysis_result)

    assert result["letter_grade"] == "A+"
    assert result["headers_present"] == 10
    assert result["headers_missing"] == 0
    assert result["total_score"] >= 90


def test_score_calculation_missing_all():
    analysis_result = {
        "https": False,
        "error": None,
        "headers_analysis": analyze_headers({}),
    }

    result = calculate_score(analysis_result)

    assert result["letter_grade"] == "F"
    assert result["headers_present"] == 0
    assert result["headers_missing"] == 10
    assert len(result["critical_issues"]) > 0


def test_letter_grade_boundaries():
    assert letter_grade(100) == "A+"
    assert letter_grade(90) == "A+"
    assert letter_grade(89.99) == "A"
    assert letter_grade(80) == "A"
    assert letter_grade(79.99) == "B"
    assert letter_grade(70) == "B"
    assert letter_grade(69.99) == "C"
    assert letter_grade(60) == "C"
    assert letter_grade(59.99) == "D"
    assert letter_grade(50) == "D"
    assert letter_grade(49.99) == "F"
    assert letter_grade(0) == "F"
