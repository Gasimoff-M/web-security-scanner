# 🕷️ Web Uygulama Güvenlik Tarayıcı

Web uygulamalarındaki **SQL Injection** ve **XSS** zafiyetlerini otomatik olarak tespit eden Python tabanlı bir güvenlik tarama aracı.

## 🚀 Özellikler

- Otomatik form keşfi ve analizi
- SQL Injection testi (8 farklı payload)
- XSS (Cross-Site Scripting) testi (6 farklı payload)
- Sayfa içi linkleri otomatik tarama
- Renkli terminal çıktısı
- Detaylı zafiyet raporu

## 📦 Kurulum

```bash
git clone https://github.com/Gasimoff-M/web-security-scanner
cd web-security-scanner
pip install requests beautifulsoup4
python web_scanner.py
```

## 💻 Kullanım

```
╔══════════════════════════════════════════╗
║    Web Uygulama Güvenlik Tarayıcı v1.0   ║
║         github.com/Gasimoff-M            ║
╚══════════════════════════════════════════╝

  Hedef URL girin: http://testphp.vulnweb.com
```

## 📊 Örnek Çıktı

```
  [*] Sayfa linkleri taranıyor...
  [*] 5 sayfa bulundu.

  [→] Test ediliyor: http://testphp.vulnweb.com/login.php
  [*] SQL Injection testi başlıyor...
  [!] SQL Injection bulundu! Payload: ' OR '1'='1
  [*] XSS testi başlıyor...
  [!] XSS açığı bulundu! Payload: <script>alert('XSS')</script>

=======================================================
  TARAMA RAPORU — 02.05.2025 14:35
  Hedef: http://testphp.vulnweb.com
=======================================================
  [!] Toplam 2 zafiyet tespit edildi:

  1. Tür    : SQL Injection
     URL    : http://testphp.vulnweb.com/login.php
     Payload: ' OR '1'='1

  2. Tür    : XSS
     URL    : http://testphp.vulnweb.com/search.php
     Payload: <script>alert('XSS')</script>
```

## 🧪 Test Ortamı

Aracı güvenli şekilde test etmek için:
- [http://testphp.vulnweb.com](http://testphp.vulnweb.com) — Acunetix'in eğitim amaçlı açık hedefi

## ⚠️ Yasal Uyarı

Bu araç yalnızca **eğitim amaçlı** ve **izin verilen sistemlerde** kullanım içindir.
İzinsiz sistemleri taramak yasadışıdır.

## 👤 Geliştirici

**Gasimoff-M** — [github.com/Gasimoff-M](https://github.com/Gasimoff-M)
