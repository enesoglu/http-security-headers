"""URL'lerden HTTP başlıklarını çeken ve güvenlik açısından değerlendiren analiz motoru.

Bu modül iki ana fonksiyon sunar:

* :func:`analyze_url` - bir URL'e istek atar, yönlendirmeleri takip eder ve
  bağlantı/yanıt bilgilerini toplar.
* :func:`analyze_headers` - toplanan HTTP başlıklarını
  :data:`src.headers_config.SECURITY_HEADERS` kurallarına göre değerlendirir.
"""

from __future__ import annotations

import time
from typing import Any

import requests
from requests.exceptions import ConnectionError, RequestException, SSLError, Timeout

from src.headers_config import SECURITY_HEADERS

USER_AGENT = "SecurityHeadersAnalyzer/1.0"
DEFAULT_TIMEOUT = 10


def analyze_url(url: str, timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Verilen URL'e istek atar ve bağlantı/yanıt bilgilerini döndürür.

    Önce HEAD isteği denenir; sunucu HEAD'i desteklemiyorsa veya hata
    döndürüyorsa GET isteğine düşülür. HTTP'den HTTPS'e yönlendirmeler
    ``requests`` tarafından otomatik takip edilir.

    Returns:
        Aşağıdaki anahtarları içeren bir sözlük::

            {
                "url": str,
                "final_url": str,
                "status_code": int | None,
                "headers": dict,
                "redirected": bool,
                "https": bool,
                "error": str | None,
                "response_time_ms": float,
            }
    """
    result: dict[str, Any] = {
        "url": url,
        "final_url": url,
        "status_code": None,
        "headers": {},
        "redirected": False,
        "https": url.lower().startswith("https://"),
        "error": None,
        "response_time_ms": 0.0,
    }

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    start = time.perf_counter()

    try:
        try:
            response = session.head(url, timeout=timeout, allow_redirects=True)
            if response.status_code >= 400 or not response.headers:
                response = session.get(url, timeout=timeout, allow_redirects=True)
        except RequestException:
            response = session.get(url, timeout=timeout, allow_redirects=True)

        result["status_code"] = response.status_code
        result["final_url"] = response.url
        result["headers"] = dict(response.headers)
        result["redirected"] = bool(response.history) or response.url != url
        result["https"] = response.url.lower().startswith("https://")

    except SSLError:
        result["error"] = "SSL sertifika hatası: Sitenin SSL sertifikası doğrulanamadı."
    except Timeout:
        result["error"] = f"Bağlantı zaman aşımına uğradı ({timeout} saniye)."
    except ConnectionError:
        result["error"] = "Bağlantı kurulamadı: Sunucuya erişilemiyor veya adres çözümlenemiyor."
    except RequestException as exc:
        result["error"] = f"İstek sırasında bir hata oluştu: {exc}"
    finally:
        result["response_time_ms"] = round((time.perf_counter() - start) * 1000, 2)
        session.close()

    return result


def analyze_headers(headers: dict[str, str]) -> dict[str, dict[str, Any]]:
    """Verilen HTTP başlıklarını :data:`SECURITY_HEADERS` kurallarına göre değerlendirir.

    Args:
        headers: HTTP yanıt başlıkları (anahtar büyük/küçük harf duyarsız ele alınır).

    Returns:
        Her güvenlik başlığı için ``{"present", "value", "valid", "score", "issues"}``
        içeren bir sözlük.
    """
    # Sunucudan gelen başlık adlarının büyük/küçük harf farklılıklarını ortadan
    # kaldırmak için küçük harfli bir eşleme oluştur.
    headers_lower = {key.lower(): value for key, value in headers.items()}

    results: dict[str, dict[str, Any]] = {}

    for header_name, config in SECURITY_HEADERS.items():
        value = headers_lower.get(header_name.lower())
        validation = config["validator"](value)

        results[header_name] = {
            "present": value is not None,
            "value": value or "",
            "valid": validation["valid"],
            "score": validation["score"],
            "issues": validation["issues"],
        }

    return results
