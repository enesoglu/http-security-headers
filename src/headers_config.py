"""HTTP güvenlik başlıkları için kural ve doğrulama (validator) tanımları.

Bu modül, analiz edilecek her güvenlik başlığının ağırlığını, açıklamasını,
karşı koyduğu tehditleri ve değerini doğrulayan fonksiyonu içeren
``SECURITY_HEADERS`` sözlüğünü tanımlar.

Her validator fonksiyonu, başlığın ham değerini (``str`` veya ``None``) alır
ve şu yapıda bir sözlük döndürür::

    {
        "valid": bool,        # başlık güvenlik açısından kabul edilebilir mi
        "score": float,       # 0.0 - 1.0 arası kalite skoru
        "issues": list[str],  # Türkçe açıklamalı tespitler/öneriler
    }
"""

from __future__ import annotations

# Bir yıl, saniye cinsinden (HSTS max-age önerisi için kullanılır).
ONE_YEAR_SECONDS = 31536000


def validate_hsts(value: str | None) -> dict:
    """Strict-Transport-Security başlığını doğrular."""
    issues: list[str] = []

    if not value:
        return {
            "valid": False,
            "score": 0.0,
            "issues": ["Strict-Transport-Security başlığı eksik."],
        }

    directives = [d.strip().lower() for d in value.split(";") if d.strip()]

    max_age = None
    for directive in directives:
        if directive.startswith("max-age"):
            parts = directive.split("=", 1)
            if len(parts) == 2:
                try:
                    max_age = int(parts[1].strip())
                except ValueError:
                    max_age = None

    has_subdomains = "includesubdomains" in directives
    has_preload = "preload" in directives

    if max_age is None:
        issues.append("max-age direktifi eksik veya geçersiz.")
        return {"valid": False, "score": 0.0, "issues": issues}

    if max_age >= ONE_YEAR_SECONDS:
        score = 0.7
        valid = True
    elif max_age > 0:
        score = round(0.4 * (max_age / ONE_YEAR_SECONDS), 2)
        valid = False
        issues.append(
            f"max-age değeri ({max_age}) önerilen 1 yıldan (31536000 saniye) az."
        )
    else:
        score = 0.0
        valid = False
        issues.append("max-age değeri 0 veya negatif; HSTS etkin değil.")

    if has_subdomains:
        score += 0.15
    else:
        issues.append("includeSubDomains direktifi eksik.")

    if has_preload:
        score += 0.15
    else:
        issues.append("preload direktifi eksik (tarayıcı ön yükleme listeleri için önerilir).")

    score = max(0.0, min(round(score, 2), 1.0))

    return {"valid": valid, "score": score, "issues": issues}


def validate_csp(value: str | None) -> dict:
    """Content-Security-Policy başlığını doğrular."""
    issues: list[str] = []

    if not value:
        return {
            "valid": False,
            "score": 0.0,
            "issues": ["Content-Security-Policy başlığı eksik."],
        }

    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]

    has_default_src = "default-src" in directives
    has_script_src = "script-src" in directives

    if not has_default_src and not has_script_src:
        issues.append("default-src veya script-src direktifi tanımlanmamış.")
        return {"valid": False, "score": 0.1, "issues": issues}

    score = 0.7

    relevant_values: list[str] = []
    relevant_values += directives.get("default-src", [])
    relevant_values += directives.get("script-src", [])

    if "'unsafe-inline'" in relevant_values:
        issues.append("'unsafe-inline' kullanımı XSS riskini önemli ölçüde artırır.")
        score -= 0.25

    if "'unsafe-eval'" in relevant_values:
        issues.append("'unsafe-eval' kullanımı kod enjeksiyonu riskini artırır.")
        score -= 0.2

    if "*" in relevant_values:
        issues.append("Joker karakter (*) kullanımı kaynak kısıtlamasını zayıflatır.")
        score -= 0.2

    score = max(0.0, min(round(score, 2), 1.0))
    valid = score >= 0.4

    return {"valid": valid, "score": score, "issues": issues}


def validate_xfo(value: str | None) -> dict:
    """X-Frame-Options başlığını doğrular."""
    issues: list[str] = []

    if not value:
        return {
            "valid": False,
            "score": 0.0,
            "issues": ["X-Frame-Options başlığı eksik."],
        }

    value_clean = value.strip().upper()

    if value_clean in ("DENY", "SAMEORIGIN"):
        return {"valid": True, "score": 1.0, "issues": issues}

    if value_clean.startswith("ALLOW-FROM"):
        issues.append(
            "ALLOW-FROM yönergesi modern tarayıcılarda desteklenmiyor; "
            "DENY veya SAMEORIGIN kullanılmalı."
        )
        return {"valid": False, "score": 0.3, "issues": issues}

    issues.append(
        f"Geçersiz X-Frame-Options değeri: '{value}'. DENY veya SAMEORIGIN kullanılmalı."
    )
    return {"valid": False, "score": 0.0, "issues": issues}


def validate_xcto(value: str | None) -> dict:
    """X-Content-Type-Options başlığını doğrular."""
    issues: list[str] = []

    if not value:
        return {
            "valid": False,
            "score": 0.0,
            "issues": ["X-Content-Type-Options başlığı eksik."],
        }

    if value.strip().lower() == "nosniff":
        return {"valid": True, "score": 1.0, "issues": issues}

    issues.append(
        f"Geçersiz X-Content-Type-Options değeri: '{value}'. 'nosniff' kullanılmalı."
    )
    return {"valid": False, "score": 0.0, "issues": issues}


# Sıkı politikalar: bilgi sızıntısını en aza indirir.
_STRICT_REFERRER_POLICIES = {
    "no-referrer",
    "strict-origin-when-cross-origin",
    "same-origin",
    "strict-origin",
}

# Kabul edilebilir ama daha az sıkı politikalar.
_ACCEPTABLE_REFERRER_POLICIES = {
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
}


def validate_referrer_policy(value: str | None) -> dict:
    """Referrer-Policy başlığını doğrular."""
    issues: list[str] = []

    if not value:
        return {
            "valid": False,
            "score": 0.0,
            "issues": ["Referrer-Policy başlığı eksik."],
        }

    # Virgülle ayrılmış birden fazla (fallback) değer olabilir; tarayıcı
    # geçersiz olanları atlayıp son geçerli değeri kullanır.
    tokens = [t.strip().lower() for t in value.replace(",", " ").split() if t.strip()]
    policy = tokens[-1] if tokens else value.strip().lower()

    if policy in _STRICT_REFERRER_POLICIES:
        return {"valid": True, "score": 1.0, "issues": issues}

    if policy in _ACCEPTABLE_REFERRER_POLICIES:
        issues.append(
            f"'{policy}' kabul edilebilir ancak daha sıkı bir politika "
            "(örn. strict-origin-when-cross-origin) önerilir."
        )
        return {"valid": True, "score": 0.6, "issues": issues}

    if policy == "unsafe-url":
        issues.append(
            "'unsafe-url' referrer bilgisini her zaman gönderir; bilgi sızıntısı riski taşır."
        )
        return {"valid": False, "score": 0.0, "issues": issues}

    issues.append(f"Tanınmayan Referrer-Policy değeri: '{value}'.")
    return {"valid": False, "score": 0.2, "issues": issues}


def validate_permissions_policy(value: str | None) -> dict:
    """Permissions-Policy başlığını doğrular."""
    issues: list[str] = []

    if not value:
        return {
            "valid": False,
            "score": 0.0,
            "issues": ["Permissions-Policy başlığı eksik."],
        }

    directives = [d.strip() for d in value.split(",") if d.strip()]

    if not directives:
        issues.append("Permissions-Policy başlığında en az bir politika tanımlanmalı.")
        return {"valid": False, "score": 0.0, "issues": issues}

    return {"valid": True, "score": 1.0, "issues": issues}


def validate_xss_protection(value: str | None) -> dict:
    """X-XSS-Protection başlığını doğrular (legacy, sadece bilgi amaçlı)."""
    issues: list[str] = []

    if not value:
        issues.append(
            "X-XSS-Protection başlığı eksik (legacy bir başlıktır; "
            "modern tarayıcılarda CSP kullanılması önerilir)."
        )
        return {"valid": False, "score": 0.5, "issues": issues}

    value_clean = value.strip().lower()

    if value_clean.startswith("1"):
        issues.append(
            "X-XSS-Protection legacy bir başlıktır; modern korunma için CSP önerilir."
        )
        return {"valid": True, "score": 1.0, "issues": issues}

    if value_clean.startswith("0"):
        issues.append(
            "X-XSS-Protection devre dışı bırakılmış (0). Legacy bir başlıktır, "
            "CSP kullanılması önerilir."
        )
        return {"valid": True, "score": 0.5, "issues": issues}

    issues.append(f"Tanınmayan X-XSS-Protection değeri: '{value}'.")
    return {"valid": False, "score": 0.3, "issues": issues}


def validate_coop(value: str | None) -> dict:
    """Cross-Origin-Opener-Policy başlığını doğrular."""
    issues: list[str] = []

    if not value:
        return {
            "valid": False,
            "score": 0.0,
            "issues": ["Cross-Origin-Opener-Policy başlığı eksik."],
        }

    value_clean = value.strip().lower()

    if value_clean == "same-origin":
        return {"valid": True, "score": 1.0, "issues": issues}

    if value_clean == "same-origin-allow-popups":
        issues.append(
            "'same-origin-allow-popups' kısmi izolasyon sağlar; mümkünse "
            "'same-origin' kullanılmalı."
        )
        return {"valid": True, "score": 0.6, "issues": issues}

    if value_clean == "unsafe-none":
        issues.append("'unsafe-none' izolasyon sağlamaz; 'same-origin' önerilir.")
        return {"valid": False, "score": 0.0, "issues": issues}

    issues.append(f"Tanınmayan Cross-Origin-Opener-Policy değeri: '{value}'.")
    return {"valid": False, "score": 0.2, "issues": issues}


def validate_coep(value: str | None) -> dict:
    """Cross-Origin-Embedder-Policy başlığını doğrular."""
    issues: list[str] = []

    if not value:
        return {
            "valid": False,
            "score": 0.0,
            "issues": ["Cross-Origin-Embedder-Policy başlığı eksik."],
        }

    value_clean = value.strip().lower()

    if value_clean in ("require-corp", "credentialless"):
        return {"valid": True, "score": 1.0, "issues": issues}

    if value_clean == "unsafe-none":
        issues.append(
            "'unsafe-none' izolasyon sağlamaz; 'require-corp' veya 'credentialless' önerilir."
        )
        return {"valid": False, "score": 0.0, "issues": issues}

    issues.append(f"Tanınmayan Cross-Origin-Embedder-Policy değeri: '{value}'.")
    return {"valid": False, "score": 0.2, "issues": issues}


def validate_corp(value: str | None) -> dict:
    """Cross-Origin-Resource-Policy başlığını doğrular."""
    issues: list[str] = []

    if not value:
        return {
            "valid": False,
            "score": 0.0,
            "issues": ["Cross-Origin-Resource-Policy başlığı eksik."],
        }

    value_clean = value.strip().lower()

    if value_clean == "cross-origin":
        issues.append(
            "'cross-origin' kaynakların başka sitelerce okunmasına izin verir; "
            "mümkünse 'same-origin' veya 'same-site' kullanılmalı."
        )
        return {"valid": True, "score": 0.6, "issues": issues}

    if value_clean in ("same-origin", "same-site"):
        return {"valid": True, "score": 1.0, "issues": issues}

    issues.append(f"Tanınmayan Cross-Origin-Resource-Policy değeri: '{value}'.")
    return {"valid": False, "score": 0.0, "issues": issues}


SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "name": "Strict-Transport-Security",
        "weight": 20,
        "description": (
            "Tarayıcıya, siteye yalnızca HTTPS üzerinden bağlanması gerektiğini "
            "bildirir; HTTP'ye düşürme girişimlerini önler."
        ),
        "protects_against": [
            "Ortadaki adam (MITM) saldırıları",
            "SSL stripping",
        ],
        "validator": validate_hsts,
    },
    "Content-Security-Policy": {
        "name": "Content-Security-Policy",
        "weight": 25,
        "description": (
            "Sayfanın hangi kaynaklardan içerik (script, stil, resim vb.) "
            "yükleyebileceğini kısıtlar."
        ),
        "protects_against": [
            "Cross-Site Scripting (XSS)",
            "Veri enjeksiyonu (data injection)",
        ],
        "validator": validate_csp,
    },
    "X-Frame-Options": {
        "name": "X-Frame-Options",
        "weight": 15,
        "description": "Sayfanın başka sitelerde iframe içine yerleştirilmesini kontrol eder.",
        "protects_against": ["Clickjacking"],
        "validator": validate_xfo,
    },
    "X-Content-Type-Options": {
        "name": "X-Content-Type-Options",
        "weight": 10,
        "description": (
            "Tarayıcının, sunucunun belirttiği Content-Type dışında bir tür "
            "tahmin etmesini (MIME sniffing) engeller."
        ),
        "protects_against": ["MIME sniffing"],
        "validator": validate_xcto,
    },
    "Referrer-Policy": {
        "name": "Referrer-Policy",
        "weight": 10,
        "description": (
            "Bağlantı tıklandığında veya kaynak istendiğinde gönderilecek "
            "Referer bilgisinin kapsamını belirler."
        ),
        "protects_against": ["Bilgi sızıntısı (referrer leakage)"],
        "validator": validate_referrer_policy,
    },
    "Permissions-Policy": {
        "name": "Permissions-Policy",
        "weight": 10,
        "description": (
            "Kamera, mikrofon, konum gibi tarayıcı özelliklerine erişimi "
            "kısıtlar."
        ),
        "protects_against": [
            "Yetkisiz tarayıcı özelliği/API kullanımı",
        ],
        "validator": validate_permissions_policy,
    },
    "X-XSS-Protection": {
        "name": "X-XSS-Protection",
        "weight": 5,
        "description": (
            "Eski tarayıcılardaki yerleşik XSS filtresini kontrol eden, "
            "günümüzde önemini kaybetmiş (legacy) bir başlıktır."
        ),
        "protects_against": ["Cross-Site Scripting (XSS) - legacy tarayıcılar"],
        "validator": validate_xss_protection,
    },
    "Cross-Origin-Opener-Policy": {
        "name": "Cross-Origin-Opener-Policy",
        "weight": 5,
        "description": (
            "Sayfanın tarayıcı sekme grubunu (browsing context group) "
            "farklı kökenli pencerelerden izole eder."
        ),
        "protects_against": [
            "Cross-origin pencere referansı saldırıları (Spectre vb.)",
        ],
        "validator": validate_coop,
    },
    "Cross-Origin-Embedder-Policy": {
        "name": "Cross-Origin-Embedder-Policy",
        "weight": 5,
        "description": (
            "Sayfanın, açıkça izin vermeyen cross-origin kaynakları "
            "yüklemesini engeller."
        ),
        "protects_against": [
            "Cross-origin veri sızıntısı (Spectre vb. yan kanal saldırıları)",
        ],
        "validator": validate_coep,
    },
    "Cross-Origin-Resource-Policy": {
        "name": "Cross-Origin-Resource-Policy",
        "weight": 5,
        "description": (
            "Kaynağın hangi kökenler tarafından yüklenebileceğini "
            "kısıtlar."
        ),
        "protects_against": [
            "Cross-origin kaynak hırsızlığı",
        ],
        "validator": validate_corp,
    },
}
