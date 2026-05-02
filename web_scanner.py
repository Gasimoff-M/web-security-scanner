# =====================================================
# Web Uygulama Güvenlik Tarayıcı
# Geliştirici: Gasimoff-M
# Açıklama: Web uygulamalarında SQL Injection ve XSS
#            zafiyetlerini otomatik olarak test eder
# =====================================================

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from datetime import datetime

# ─── Renk Kodları (Terminal çıktısı için) ──────────────
KIRMIZI = "\033[91m"
YESIL   = "\033[92m"
SARI    = "\033[93m"
MAVI    = "\033[94m"
SIFIRLA = "\033[0m"

# ─── SQL Injection Test Payloadları ────────────────────
SQL_PAYLOADLAR = [
    "'",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1 --",
    "\" OR \"1\"=\"1",
    "admin' --",
    "1' ORDER BY 1--",
    "1 UNION SELECT null--",
]

# ─── XSS Test Payloadları ──────────────────────────────
XSS_PAYLOADLAR = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "'><script>alert('XSS')</script>",
    "<body onload=alert('XSS')>",
]

# Bulunan zafiyetleri sakla
zafiyetler = []


def formlari_al(url, oturum):
    """
    Verilen URL'deki tüm HTML formlarını bulup döndürür.
    """
    try:
        yanit = oturum.get(url, timeout=10)
        soup = BeautifulSoup(yanit.content, "html.parser")
        return soup.find_all("form")
    except Exception as e:
        print(f"{KIRMIZI}  [!] Form alınamadı: {e}{SIFIRLA}")
        return []


def form_detay(form):
    """
    Formun action URL'sini ve input alanlarını çıkarır.
    """
    detay = {}
    detay["action"] = form.attrs.get("action", "").lower()
    detay["metod"]  = form.attrs.get("method", "get").lower()
    detay["inputler"] = []

    for input_tag in form.find_all("input"):
        tip  = input_tag.attrs.get("type", "text")
        isim = input_tag.attrs.get("name")
        deger = input_tag.attrs.get("value", "test")
        detay["inputler"].append({"tip": tip, "isim": isim, "deger": deger})

    return detay


def form_gonder(oturum, url, detay, payload):
    """
    Forma payload ekleyerek GET veya POST isteği gönderir.
    """
    hedef_url = urljoin(url, detay["action"])
    veri = {}

    for input_alan in detay["inputler"]:
        if input_alan["isim"]:
            # Her input alanına payload yerleştir
            if input_alan["tip"] in ("text", "search", "email", "password"):
                veri[input_alan["isim"]] = payload
            else:
                veri[input_alan["isim"]] = input_alan["deger"]

    try:
        if detay["metod"] == "post":
            return oturum.post(hedef_url, data=veri, timeout=10)
        else:
            return oturum.get(hedef_url, params=veri, timeout=10)
    except Exception:
        return None


def sql_injection_test(url, oturum):
    """
    Formlara SQL Injection payloadları göndererek
    veritabanı hata mesajlarını arar.
    """
    print(f"\n{MAVI}  [*] SQL Injection testi başlıyor...{SIFIRLA}")
    formlar = formlari_al(url, oturum)

    # Hata mesajı anahtar kelimeleri
    sql_hatalari = [
        "sql", "mysql", "syntax error", "unclosed quotation",
        "odbc", "sqlite", "postgresql", "ora-", "microsoft jet"
    ]

    for form in formlar:
        detay = form_detay(form)
        for payload in SQL_PAYLOADLAR:
            yanit = form_gonder(oturum, url, detay, payload)
            if yanit:
                icerik = yanit.text.lower()
                for hata in sql_hatalari:
                    if hata in icerik:
                        mesaj = f"SQL Injection bulundu! Payload: {payload}"
                        print(f"{KIRMIZI}  [!] {mesaj}{SIFIRLA}")
                        zafiyetler.append({"tur": "SQL Injection", "url": url, "payload": payload})
                        break


def xss_test(url, oturum):
    """
    Formlara XSS payloadları göndererek
    yanıtta payload'ın yansıyıp yansımadığını kontrol eder.
    """
    print(f"\n{MAVI}  [*] XSS testi başlıyor...{SIFIRLA}")
    formlar = formlari_al(url, oturum)

    for form in formlar:
        detay = form_detay(form)
        for payload in XSS_PAYLOADLAR:
            yanit = form_gonder(oturum, url, detay, payload)
            if yanit and payload in yanit.text:
                mesaj = f"XSS açığı bulundu! Payload: {payload}"
                print(f"{KIRMIZI}  [!] {mesaj}{SIFIRLA}")
                zafiyetler.append({"tur": "XSS", "url": url, "payload": payload})


def linkleri_tara(url, oturum):
    """
    Sayfadaki tüm iç linkleri bulur.
    """
    try:
        yanit = oturum.get(url, timeout=10)
        soup = BeautifulSoup(yanit.content, "html.parser")
        linkler = set()
        domain = urlparse(url).netloc

        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            tam_url = urljoin(url, href)
            # Sadece aynı domain'deki linkleri al
            if urlparse(tam_url).netloc == domain:
                linkler.add(tam_url)

        return linkler
    except Exception:
        return set()


def rapor_yaz(hedef):
    """
    Tarama sonuçlarını ekrana raporlar.
    """
    print("\n" + "=" * 55)
    print(f"  TARAMA RAPORU — {datetime.now().strftime('%d.%m.%Y %H:%M')}")
    print(f"  Hedef: {hedef}")
    print("=" * 55)

    if not zafiyetler:
        print(f"{YESIL}  [✓] Zafiyet bulunamadı.{SIFIRLA}")
    else:
        print(f"{KIRMIZI}  [!] Toplam {len(zafiyetler)} zafiyet tespit edildi:{SIFIRLA}\n")
        for i, z in enumerate(zafiyetler, 1):
            print(f"  {i}. Tür    : {z['tur']}")
            print(f"     URL    : {z['url']}")
            print(f"     Payload: {z['payload']}\n")

    print("=" * 55)


# ─── Ana Program ───────────────────────────────────────
if __name__ == "__main__":
    print(f"\n{MAVI}╔══════════════════════════════════════════╗")
    print("║    Web Uygulama Güvenlik Tarayıcı v1.0   ║")
    print("║         github.com/Gasimoff-M            ║")
    print(f"╚══════════════════════════════════════════╝{SIFIRLA}")
    print(f"{SARI}")
    print("  ⚠️  UYARI: Bu araç yalnızca izin verilen")
    print("  sistemlerde kullanılmalıdır!")
    print(f"{SIFIRLA}")

    hedef = input("  Hedef URL girin (örn: http://testphp.vulnweb.com): ").strip()

    if not hedef.startswith("http"):
        hedef = "http://" + hedef

    # HTTP oturumu oluştur
    oturum = requests.Session()
    oturum.headers["User-Agent"] = "Mozilla/5.0 (SecurityScanner/1.0)"

    print(f"\n{YESIL}  [*] Sayfa linkleri taranıyor...{SIFIRLA}")
    linkler = linkleri_tara(hedef, oturum)
    linkler.add(hedef)  # Ana sayfayı da ekle
    print(f"  [*] {len(linkler)} sayfa bulundu.")

    # Her sayfa için testleri çalıştır
    for link in linkler:
        print(f"\n{MAVI}  [→] Test ediliyor: {link}{SIFIRLA}")
        sql_injection_test(link, oturum)
        xss_test(link, oturum)

    # Raporu yazdır
    rapor_yaz(hedef)
