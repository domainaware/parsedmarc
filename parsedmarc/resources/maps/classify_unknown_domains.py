#!/usr/bin/env python
"""Classify rows from a `collect_domain_info.py` TSV into map / known-unknown.

Reads a TSV produced by `collect_domain_info.py` and applies a regex-based
multilingual classifier to each row's WHOIS, page title, page description,
and MMDB `as_name` to choose a `(name, type)` tuple — or send the domain to
the known-unknown list if no detector fires.

The classifier serves both lookup paths into `base_reverse_dns_map.csv`:

- The original purpose — classifying reverse-DNS *base domains* derived
  from the source IPs of DMARC reports (the `base_reverse_dns.csv` →
  `unknown_base_reverse_dns.csv` flow described in
  `find_unknown_base_reverse_dns.py`). These are PTR-side keys; the regex
  detectors fire equally on a residential ISP's PTR base or a SaaS
  provider's PTR base.
- The MMDB-coverage flow — classifying ASN domains lifted from the
  bundled IPinfo Lite MMDB to populate the ASN-fallback lookup path.
  The classifier was originally built up in `/tmp/classify_b<N>.py`
  across the b5–b13 batches that brought distinct AS-domain coverage
  from ~10% to ~50%; committing it lets future batches inherit the
  multilingual keyword work rather than re-deriving it from scratch
  each session.

Per AGENTS.md the historical workflow is "feed the TSV to an LLM
classifier (or skim it by hand)" — this script is the regex baseline that
catches obvious cases at scale and leaves only the genuinely ambiguous to
manual / LLM review.

Detectors cover all 44 industry types listed in `README.md` (every type
defined for `base_reverse_dns_map.csv`'s `type` column). Every detector
aims for concept-translation parity across the same broad language pool
(typically 25–35 languages including major Romance, Germanic, Slavic,
Turkic, Greek, Semitic, Indic, East Asian, Southeast Asian, and Bantu
languages). Each language carries the natural compound terms that a
native speaker would actually use for the concept — e.g. "tire shop" is
present as `tire shop` / `tyre shop` (US/UK) plus `pneuservis` (cs/sk),
`шиномонтаж` (ru), `lastik bayii` (tr), `gommista` (it), `vulkanizer`
(hr/sr/bs), and `タイヤ販売` (ja), but is *not* artificially translated
into languages where no idiomatic compound exists.

Each successive batch / drift sweep is expected to refine the keyword
coverage further as new patterns surface in the unclassified pool.

Brand-name selection prefers (in order): MMDB `as_name` for the domain;
the page title's first segment; non-redacted WHOIS registrant org;
domain-derived fallback. A `clean_brand` step strips legal-form suffixes
(LLC / GmbH / Ltda / EIRELI / sp. z o.o. / etc.) and prefixes (PT, OOO,
LLC). Brands captured from titles prefer the segment that contains the
domain root, so e.g. accessmontana.com whose as_name is "MONTANA WEST,
L.L.C." but whose title is "Internet, Phone & TV Bundles | Access
Montana" maps to "Access Montana", not "Montana West".

Usage:
    cd parsedmarc/resources/maps
    python classify_unknown_domains.py \\
        -i /tmp/batch_info.tsv \\
        --map-out /tmp/additions.csv \\
        --ku-out /tmp/ku_additions.txt

Outputs:
    --map-out: three-column CSV (domain, name, type) — append to
        base_reverse_dns_map.csv
    --ku-out: one domain per line — append to known_unknown_base_reverse_dns.txt

The HAND dict at the top of the file is an extension point for explicit
overrides (e.g. acquisition aliases, brand-name corrections). It is empty
by default; populate it for batch-specific cases that the regex can't
handle.
"""

import argparse
import csv
import os
import re
import sys

import maxminddb

# Repo-relative default for the MMDB.
_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_MMDB = os.path.normpath(os.path.join(_HERE, "..", "ipinfo", "ipinfo_lite.mmdb"))

# Per-batch HAND overrides go here. Each entry is:
#   "domain.example": ("Brand Name", "Type")
#       — explicit (name, type) classification
#   "domain.example": "KU"
#       — force into known-unknown
#   "domain.example": None
#       — silently drop (do not classify, do not record)
# This is checked before the auto-classifier; HAND wins.
HAND: dict = {}

# Mojibake fixes — collect_domain_info.py occasionally double-encodes UTF-8 as
# Latin-1, so accented chars look like "Ã³" / "Ã¡" / "Ã©" / "Ã­" etc. in the
# captured text. We undo a small set of the most common cases before keyword
# matching so Spanish/Portuguese/French ISP/Web-Host pages still classify.
_MOJIBAKE = [
    ("Ã³", "ó"),
    ("Ã¡", "á"),
    ("Ã©", "é"),
    ("Ã­", "í"),
    ("Ã±", "ñ"),
    ("Ãº", "ú"),
    ("Ã¼", "ü"),
    ("Ã§", "ç"),
    ("Ã ", "à"),
    ("Ã¨", "è"),
    ("Ã”", "Ô"),
    ("Ã“", "Ó"),
    ("Ã‘", "Ñ"),
    ("Ã‰", "É"),
]


def fix_text(s: str) -> str:
    for bad, good in _MOJIBAKE:
        if bad in s:
            s = s.replace(bad, good)
    return s


# ISP — wide net. Almost any ISP-style keyword is enough since these are all
# ASN-registered network operators. Bare "fibra" / "fiber" / "telecom" is
# acceptably unique in homepage context.
ISP_RE = re.compile(
    r"(?i)\b("
    # English
    r"isp|wisp|telco|catv|voip|"
    r"broadband|fiber|fibre|"
    r"gpon|xdsl|adsl|vdsl|fttp|ftth|fttx|"
    r"wifi|wi-fi|wireless internet|managed wifi|"
    r"cable tv|cable internet|"
    r"telecom|telcomm|"
    r"internet provider|internet service provider|"
    r"residential internet|business internet|home internet|"
    r"high[ -]speed internet|"
    r"phone (?:&|and) internet|internet (?:&|and) phone|"
    r"internet, phone|phone, internet|"
    r"mobile network|cellular network|cellular service provider|"
    r"satellite internet|fixed wireless|"
    # Spanish
    r"proveedor de internet|servicio de internet|"
    r"banda ancha|fibra (?:óptica|optica)|fibra|"
    r"telefonía móvil|telefonía celular|"
    r"telecomunicaci|telecomunicaciones|"
    # Portuguese
    r"provedor de internet|provedor de banda larga|"
    r"banda larga|fibra ó?ptica|"
    r"telefonia móvel|telecomunicações|"
    r"internet rápida|internet rapida|"
    # French
    r"fournisseur d'?accès internet|fournisseur internet|fai\b|"
    r"fibre optique|haut[ -]débit|"
    r"opérateur télécom|téléphonie mobile|"
    # Italian
    r"fornitore (?:di )?internet|operatore (?:di )?telefonia|"
    r"banda larga|fibra ottica|telecomunicazioni|"
    # German
    r"internetanbieter|internet[- ]provider|"
    r"breitband|glasfaser(?:anschluss)?|"
    r"telekom|telekommunikation|festnetz|mobilfunk|"
    # Dutch
    r"internetaanbieder|breedband|glasvezel|"
    # Russian
    r"интернет[- ]?провайдер|провайдер интернет|провайдер|"
    r"широкополосный|оптический интернет|"
    r"телеком|телекоммуникации|оператор связи|"
    r"мобильный оператор|кабельное телевидение|"
    # Polish
    r"dostawca internetu|usługi internetowe|"
    r"telewizja kablowa|telewizja|"
    r"światłowód|swiatlowod|szerokopasmowy|"
    r"operator telekomunikacyjny|"
    # Czech
    r"poskytovatel internetu|vysokorychlostní internet|"
    r"telekomunikační|kabelová televize|"
    # Slovak
    r"poskytovateľ internetu|"
    # Romanian
    r"furnizor de internet|"
    # Turkish
    r"internet servis|hizmet sağlayıcı|geniş bant|"
    r"telekomünikasyon|fiber optik|kablo tv|"
    # Greek
    r"πάροχος internet|πάροχος διαδικτύου|"
    r"τηλεπικοινωνίες|ευρυζωνικό|"
    # Chinese (Simplified and Traditional)
    r"互联网服务|互聯網服務|宽带|寬頻|光纤宽带|光纖寬頻|"
    r"电信|電信|移动通信|移動通信|有线电视|有線電視|"
    # Japanese
    r"インターネット|プロバイダ|光回線|通信事業|"
    # Korean
    r"인터넷 서비스|초고속 인터넷|광 인터넷|통신사|케이블 TV|"
    # Arabic
    r"خدمة الإنترنت|الإنترنت عريض النطاق|اتصالات|"
    # Hebrew
    r"ספק אינטרנט|תקשורת|"
    # Vietnamese
    r"nhà cung cấp internet|"
    # Indonesian
    r"penyedia layanan internet|"
    # Macedonian
    r"интернет провајдер|давател на интернет услуги|"
    r"оптички интернет|телекомуникации|кабелска телевизија|"
    r"мобилен оператор|"
    # Belarusian
    r"інтэрнэт правайдар|пастаўшчык інтэрнэт паслуг|"
    r"шырокапалосны інтэрнэт|тэлекамунікацыі|"
    r"мабільны аператар|"
    # Azerbaijani
    r"internet provayderi|internet xidməti təminatçısı|"
    r"genişzolaqlı internet|telekommunikasiya|kabel televiziyası|"
    r"mobil operator|fiber optika|"
    # Georgian
    r"ინტერნეტ პროვაიდერი|ფართოზოლოვანი ინტერნეტი|"
    r"ტელეკომუნიკაცია|საკაბელო ტელევიზია|"
    r"მობილური ოპერატორი|ოპტიკურ-ბოჭკოვანი|"
    # Armenian
    r"ինտերնետ մատակարար|ինտերնետ ծառայության մատակարար|"
    r"լայնաշերտ ինտերնետ|հեռահաղորդակցություն|"
    r"մալուխային հեռուստատեսություն|բջջային օպերատոր|"
    # Kazakh
    r"интернет провайдер|интернет қызмет жеткізуші|"
    r"кең жолақты интернет|телекоммуникация|кабельдік теледидар|"
    r"ұялы байланыс операторы|"
    # Uzbek
    r"internet provayderi|internet xizmati ko'rsatuvchi|"
    r"keng polosali internet|telekommunikatsiya|kabel televideniyesi|"
    r"mobil operator|"
    # Mongolian
    r"интернет үйлчилгээ үзүүлэгч|интернет нийлүүлэгч|"
    r"өргөн зурвасын интернет|холбоо|"
    r"кабелийн телевиз|мобайл оператор|"
    # Khmer
    r"អ្នកផ្តល់សេវាអ៊ីនធឺណិត|អ៊ីនធឺណិតលឿន|"
    r"ទូរគមនាគមន៍|ទូរទស្សន៍ខ្សែ|"
    r"ប្រតិបត្តិករទូរស័ព្ទចល័ត|"
    # Burmese
    r"အင်တာနက် ပံ့ပိုးသူ|အင်တာနက်ဝန်ဆောင်မှုပေးသူ|"
    r"လိုင်းသွယ် အင်တာနက်|ဆက်သွယ်ရေးကုမ္ပဏီ|"
    r"ကေဘယ်လ် ရုပ်မြင်သံကြား|"
    # Lao
    r"ຜູ້ໃຫ້ບໍລິການອິນເຕີເນັດ|ອິນເຕີເນັດຄວາມໄວສູງ|"
    r"ໂທລະຄົມມະນາຄົມ|ໂທລະພາບສາຍ|"
    # Nepali
    r"इन्टरनेट सेवा प्रदायक|इन्टरनेट प्रदायक|"
    r"ब्रोडब्यान्ड|दूरसंचार|केबल टेलिभिजन|"
    # Sinhala
    r"අන්තර්ජාල සේවා සපයන්නා|බ්‍රෝඩ්බෑන්ඩ්|"
    r"විදුලි සංදේශ|කේබල් රූපවාහිනිය|"
    # Amharic
    r"የኢንተርኔት አገልግሎት ሰጪ|ብሮድባንድ|"
    r"ቴሌኮሙኒኬሽን|ኬብል ቴሌቪዥን|"
    # Yoruba
    r"olùpèsè iṣẹ́ ìntánẹ́ẹ̀tì|ìntánẹ́ẹ̀tì gbígbòòrò|"
    r"ìbáraẹnisọ̀rọ̀ tẹlifón|tẹlifíṣọ̀n káàbù|"
    # Hausa
    r"mai bayar da intanet|intanet mai sauri|"
    r"sadarwa|talabijin na kebul|"
    # Igbo
    r"onye na-enye intanet|intanet|"
    r"nzikọrịta ozi|telivishọn keboul|"
    # Zulu
    r"umhlinzeki we-internet|umhlinzeki wezinsiza ze-internet|"
    r"i-broadband|ezokuxhumana|umabonakude wekhebula|"
    # Pashto
    r"د انټرنیټ خدمت تامینوونکی|پراخه انټرنیټ|"
    r"مخابرات|د کیبل تلویزیون|"
    # Kurdish
    r"pêşkêşkarê înternetê|înternetê fireh|"
    r"telekomunîkasyon|televîzyona kabloyê|"
    # Tajik
    r"провайдери интернет|интернет паҳнои зиёд|"
    r"телекоммуникатсия|телевизиони кабелӣ|"
    # Kyrgyz
    r"интернет провайдер|кенен тилкелүү интернет|"
    r"телекоммуникация|кабель телевидениеси|"
    # Maltese
    r"fornitur tal-internet|internet tal-broadband|"
    r"telekomunikazzjonijiet|televiżjoni tal-kejbil|"
    r"operatur mobbli|"
    # Luxembourgish
    r"internetanbidder|breetband|"
    r"telekommunikatioun|kabelfernsehen|mobilfunk|"
    # Haitian Creole
    r"founisè entènèt|entènèt vit|"
    r"telekominikasyon|televizyon kab|"
    # Frisian
    r"ynternetoanbieder|breedbân|"
    r"telekommunikaasje|"
    # Yiddish
    r"אינטערנעט פראַווידער|"
    r"טעלעקאמוניקאַציעס|"
    # Faroese
    r"internetveita|breiðband|"
    r"fjarskifti|"
    # Tatar
    r"интернет провайдер|телекоммуникация|"
    # Javanese
    r"penyedia internet|broadband|telekomunikasi|"
    # Sundanese
    r"panyadia internet|"
    # Cebuano
    r"tighatag sa internet|internet nga taas og bilis|"
    r"telekomunikasyon|cable tv"
    r")\b"
)

WEB_HOST_RE = re.compile(
    r"(?i)\b("
    # English
    r"web hosting|webhosting|webhost|domain hosting|shared hosting|"
    r"vps hosting|dedicated server|managed hosting|"
    r"colocation|data ?cent(?:er|re)|"
    r"cloud hosting|cloud server|cloud solutions?|cloud platform|"
    r"offshore hosting|"
    r"reseller hosting|wordpress hosting|"
    # Spanish
    r"hospedaje (?:web|de )|alojamiento web|"
    r"alojamiento de dominios|servidor dedicado|"
    r"servidor virtual|hospedaje en la nube|"
    r"servicios de colocación|centro de datos|"
    # Portuguese
    r"hospedagem|hospedagem de sites|"
    r"hospedagem de domínio|servidor dedicado|"
    r"servidor virtual|hospedagem em nuvem|"
    r"colocation|centro de dados|"
    # French
    r"hébergement|webhébergement|hébergement web|"
    r"hébergement mutualisé|hébergement de domaine|"
    r"serveur dédié|serveur virtuel|"
    r"hébergement cloud|colocation|centre de données|"
    # Italian
    r"hosting web|hosting di siti|hosting condiviso|"
    r"hosting di dominio|server dedicato|"
    r"server virtuale|hosting in cloud|"
    r"colocation|centro dati|"
    # German
    r"webhoster|rechenzentrum|webhosting[- ]?anbieter|"
    r"shared[- ]?hosting|managed[- ]?hosting|"
    r"dedizierter[- ]?server|vserver|virtueller server|"
    r"cloud[- ]?hosting|colocation[- ]dienste|"
    # Dutch
    r"webhosting|gedeelde hosting|managed hosting|"
    r"dedicated server|virtuele server|"
    r"cloudhosting|datacentrum|"
    # Polish
    r"hosting stron|centrum danych|"
    r"hosting współdzielony|hosting domeny|"
    r"serwer dedykowany|serwer wirtualny|"
    r"hosting w chmurze|kolokacja|"
    # Czech
    r"webhosting|sdílený hosting|"
    r"hosting domény|dedikovaný server|virtuální server|"
    r"cloudový hosting|datové centrum|"
    # Slovak
    r"webhosting|hosting domény|"
    r"dedikovaný server|virtuálny server|"
    r"cloudový hosting|dátové centrum|"
    # Estonian
    r"veebimajutus|jagatud majutus|"
    r"pühendatud server|virtuaalne server|"
    r"pilvemajutus|andmekeskus|"
    # Russian
    r"хостинг|центр обработки данных|"
    r"хостинг сайтов|общий хостинг|"
    r"хостинг доменов|выделенный сервер|"
    r"виртуальный сервер|облачный хостинг|"
    r"колокация|размещение серверов|дата[- ]центр|"
    # Ukrainian
    r"хостинг сайтів|центр обробки даних|"
    r"виділений сервер|віртуальний сервер|"
    r"хмарний хостинг|"
    # Bulgarian
    r"уеб хостинг|център за данни|"
    r"споделен хостинг|"
    # Romanian
    r"găzduire web|găzduire site-uri|"
    r"server dedicat|server virtual|"
    r"găzduire în cloud|centru de date|"
    # Hungarian
    r"webtárhely|tárhelyszolgáltatás|"
    r"megosztott tárhely|dedikált szerver|virtuális szerver|"
    r"felhő tárhely|adatközpont|"
    # Croatian / Serbian / Bosnian
    r"web hosting|deljeni hosting|"
    r"namenski server|virtuelni server|"
    r"cloud hosting|data centar|"
    # Slovenian
    r"spletno gostovanje|deljeno gostovanje|"
    r"namenski strežnik|virtualni strežnik|"
    r"oblačno gostovanje|podatkovni center|"
    # Greek
    r"φιλοξενία ιστοσελίδων|κοινόχρηστη φιλοξενία|"
    r"αποκλειστικός διακομιστής|εικονικός διακομιστής|"
    r"φιλοξενία cloud|κέντρο δεδομένων|"
    # Albanian
    r"strehimi i uebsajteve|qendër të dhënash|"
    # Latvian
    r"vietnes mitināšana|datu centrs|"
    # Lithuanian
    r"svetainių prieglobsčio paslaugos|duomenų centras|"
    # Finnish
    r"verkkosivuston hosting|jaettu palvelin|"
    r"oma palvelin|virtuaalipalvelin|"
    r"pilvipalvelin|palvelinkeskus|"
    # Swedish
    r"webbhotell|delad hosting|"
    r"dedikerad server|virtuell server|"
    r"molnhosting|datacenter|"
    # Norwegian
    r"webhotell|delt hosting|"
    r"dedikert server|virtuell server|"
    r"skybasert hosting|datasenter|"
    # Danish
    r"webhotel|delt hosting|"
    r"dedikeret server|virtuel server|"
    r"cloud hosting|datacenter|"
    # Icelandic
    r"vefþjónusta|gagnaver|"
    # Persian
    r"هاست وب|میزبانی وب|سرور اختصاصی|"
    r"سرور مجازی|میزبانی ابری|مرکز داده|"
    # Indonesian
    r"penyedia web hosting|hosting bersama|"
    r"server dedikasi|server virtual|"
    r"hosting cloud|pusat data|"
    # Malay
    r"hosting laman web|pelayan khusus|"
    r"pusat data|"
    # Turkish
    r"web hosting şirketi|veri merkezi|"
    r"paylaşımlı hosting|sanal sunucu|"
    r"adanmış sunucu|bulut hosting|"
    # Vietnamese
    r"lưu trữ web|hosting chia sẻ|"
    r"máy chủ riêng|máy chủ ảo|"
    r"lưu trữ đám mây|trung tâm dữ liệu|"
    # Thai
    r"เว็บโฮสติ้ง|ศูนย์ข้อมูล|"
    r"เซิร์ฟเวอร์เฉพาะ|เซิร์ฟเวอร์เสมือน|"
    # Filipino (Tagalog)
    r"web hosting|sentro ng datos|"
    # Chinese (Simplified and Traditional)
    r"虚拟主机|虛擬主機|主机服务|主機服務|"
    r"数据中心|數據中心|"
    r"独立服务器|獨立伺服器|"
    r"虚拟服务器|虛擬伺服器|"
    r"云服务器|雲端伺服器|"
    r"网站托管|網站託管|"
    # Japanese
    r"レンタルサーバー|ホスティング|データセンター|"
    r"共用サーバー|専用サーバー|仮想サーバー|"
    r"クラウドホスティング|"
    # Korean
    r"호스팅|데이터 센터|"
    r"웹 호스팅|공용 호스팅|전용 서버|"
    r"가상 서버|클라우드 호스팅|"
    # Arabic
    r"استضافة المواقع|مركز بيانات|"
    r"استضافة مشتركة|خادم مخصص|"
    r"خادم افتراضي|استضافة سحابية|"
    # Hebrew
    r"אחסון אתרים|מרכז נתונים|"
    r"שרת ייעודי|שרת וירטואלי|"
    r"אחסון בענן|"
    # Hindi
    r"वेब होस्टिंग|डेटा सेंटर|"
    r"समर्पित सर्वर|वर्चुअल सर्वर|"
    # Bengali
    r"ওয়েব হোস্টিং|ডেটা সেন্টার|"
    # Catalan
    r"allotjament web|servidor dedicat|"
    # Macedonian
    r"веб хостинг|центар за податоци|"
    r"наменски сервер|виртуелен сервер|"
    r"облачен хостинг|колокација|"
    # Belarusian
    r"вэб хостынг|цэнтр апрацоўкі дадзеных|"
    r"вылучаны сервер|віртуальны сервер|"
    r"воблачны хостынг|"
    # Azerbaijani
    r"veb hosting|veb sayt yerləşdirmə|məlumat mərkəzi|"
    r"həsr edilmiş server|virtual server|"
    r"bulud hostinqi|kollokasiya|"
    # Georgian
    r"ვებ ჰოსტინგი|მონაცემთა ცენტრი|"
    r"გამოყოფილი სერვერი|ვირტუალური სერვერი|"
    r"ღრუბლოვანი ჰოსტინგი|კოლოკაცია|"
    # Armenian
    r"վեբ հոստինգ|տվյալների կենտրոն|"
    r"հատուկ սերվեր|վիրտուալ սերվեր|"
    r"ամպային հոստինգ|կոլոկացիա|"
    # Kazakh
    r"веб хостинг|деректер орталығы|"
    r"арнайы сервер|виртуалды сервер|"
    r"бұлттық хостинг|колокация|"
    # Uzbek
    r"veb hosting|ma'lumotlar markazi|"
    r"maxsus server|virtual server|"
    r"bulutli hosting|kolokatsiya|"
    # Mongolian
    r"вэб хостинг|өгөгдлийн төв|"
    r"тусгай сервер|виртуал сервер|"
    r"үүлэн хостинг|"
    # Khmer
    r"វេបសាយហូស្ទីង|មជ្ឈមណ្ឌលទិន្នន័យ|"
    r"ម៉ាស៊ីនបម្រើឯកទេស|ម៉ាស៊ីនបម្រើនិម្មិត|"
    r"ហូស្ទីងពពក|"
    # Burmese
    r"ဝက်ဘ်ဆိုက်ဟိုစ်တင်|ဒေတာစင်တာ|"
    r"သီးသန့်ဆာဗာ|virtual ဆာဗာ|"
    # Lao
    r"ການໃຫ້ບໍລິການໂຮສຕິງ|ສູນຂໍ້ມູນ|"
    r"ເຊີບເວີສະເພາະ|ເຊີບເວີສະເໝືອນ|"
    # Nepali
    r"वेब होस्टिङ|डाटा सेन्टर|"
    r"समर्पित सर्भर|भर्चुअल सर्भर|"
    r"क्लाउड होस्टिङ|"
    # Sinhala
    r"වෙබ් සත්කාරකත්වය|දත්ත මධ්‍යස්ථානය|"
    r"කැපවූ සේවාදායකයා|අතථ්‍ය සේවාදායකයා|"
    # Amharic
    r"ድረ ገጽ ማስተናገጃ|ዳታ ማዕከል|"
    r"የተሰጠ ሰርቨር|ምናባዊ ሰርቨር|"
    # Yoruba
    r"ìgbàlejò wẹ́ẹ̀bù|ilé iṣẹ́ ìpamọ́ dátà|"
    r"àmúyé ìbínkanlé|"
    # Hausa
    r"hosting na yanar gizo|cibiyar bayanai|"
    r"sabar mai zaman kanta|sabar kama da gaske|"
    # Igbo
    r"nkwado weebụ|ebe nchekwa data|"
    # Zulu
    r"i-hosting yewebhusayithi|isikhungo sedatha|"
    r"iseva yodwa|iseva eyenziwe|"
    # Pashto
    r"د ویب میزبانۍ|د معلوماتو مرکز|"
    r"ځانگړی سرور|مجازي سرور|"
    # Kurdish
    r"hostinga torê|navenda daneyê|"
    r"servera taybetkirî|servera virtuelê|"
    # Tajik
    r"ҳостинги веб|маркази маълумот|"
    r"сервери алоҳида|сервери виртуалӣ|"
    # Kyrgyz
    r"веб хостинг|маалымат борбору|"
    r"атайын сервер|виртуалдык сервер|"
    # Maltese
    r"hosting tal-web|ċentru tad-data|"
    r"server dedikat|server virtwali|"
    r"hosting tal-cloud|kolokazzjoni|"
    # Luxembourgish
    r"webhosting|datenzenter|"
    r"dedizéierten server|virtuelle server|"
    r"cloud hosting|kolokatioun|"
    # Haitian Creole
    r"hosting wèb|sant done|"
    r"serveur dedye|serveur vityèl|"
    r"hosting nan nyaj|"
    # Frisian
    r"webhosting|datasintrum|"
    r"dedikearre tsjinner|firtuele tsjinner|"
    # Yiddish
    r"וועב האָסטינג|דאַטן צענטער|"
    # Faroese
    r"vevhýsing|datustøð|"
    r"avbýttur tænari|"
    # Tatar
    r"вэб хостинг|мәгълүмат үзәге|"
    # Javanese
    r"hosting web|pusat data|"
    r"server khusus|server virtual|"
    # Sundanese
    r"hosting wéb|"
    # Cebuano
    r"web hosting|sentro sa datos|"
    r"dedicated server|virtual server"
    r")\b"
)

EDUCATION_RE = re.compile(
    r"(?i)\b("
    # English
    r"university|college|institute of technology|polytechnic|"
    r"high school|secondary school|grammar school|"
    r"public school|private school|charter school|school district|"
    # Spanish
    r"universidad|escuela|colegio|escuela técnica|"
    # Portuguese
    r"universidade|escola|colégio|escola técnica|liceu|"
    # French
    r"université|école|collège|lycée|"
    # Italian
    r"università|scuola|liceo|"
    # German
    r"hochschule|fachhochschule|technische universität|"
    r"gymnasium|grundschule|gesamtschule|"
    # Polish
    r"szkoła|uniwersytet|akademia|"
    # Czech
    r"univerzita|škola|"
    # Russian
    r"университет|академия|вуз|институт высшего|"
    # Turkish
    r"üniversite|okul|"
    # Greek
    r"πανεπιστήμιο|σχολείο|"
    # Chinese (Simplified and Traditional both written here)
    r"大学|大學|学校|學校|"
    # Japanese (hiragana; kanji 大学 / 学校 already covered above)
    r"だいがく|がっこう|"
    # Korean
    r"대학교|대학|학교|"
    # Arabic
    r"جامعة|مدرسة|"
    # Hebrew
    r"אוניברסיטה|בית ספר|"
    # Vietnamese
    r"đại học|trường học|"
    # Indonesian
    r"universitas|sekolah|"
    # Thai
    r"มหาวิทยาลัย|โรงเรียน|"
    # Macedonian
    r"универзитет|училиште|колеџ|"
    r"средно училиште|основно училиште|"
    r"технички универзитет|политехнички|"
    # Belarusian
    r"універсітэт|школа|каледж|"
    r"сярэдняя школа|пачатковая школа|"
    r"тэхнічны універсітэт|"
    # Azerbaijani
    r"universitet|məktəb|kollec|"
    r"orta məktəb|ibtidai məktəb|"
    r"texniki universitet|politexnik institut|"
    r"təhsil müəssisəsi|"
    # Georgian
    r"უნივერსიტეტი|სკოლა|კოლეჯი|"
    r"საშუალო სკოლა|დაწყებითი სკოლა|"
    r"ტექნიკური უნივერსიტეტი|პოლიტექნიკური|"
    # Armenian
    r"համալսարան|դպրոց|քոլեջ|"
    r"միջնակարգ դպրոց|տարրական դպրոց|"
    r"տեխնիկական համալսարան|պոլիտեխնիկական|"
    # Kazakh
    r"университет|мектеп|колледж|"
    r"орта мектеп|бастауыш мектеп|"
    r"техникалық университет|политехникалық|"
    # Uzbek
    r"universitet|maktab|kollej|"
    r"o'rta maktab|boshlang'ich maktab|"
    r"texnika universiteti|politexnika institutida|"
    # Mongolian
    r"их сургууль|сургууль|коллеж|"
    r"дунд сургууль|ерөнхий боловсролын сургууль|"
    r"техникийн их сургууль|политехникийн|"
    # Khmer
    r"សាកលវិទ្យាល័យ|សាលារៀន|វិទ្យាល័យ|"
    r"អនុវិទ្យាល័យ|សាលាបឋម|"
    r"សាកលវិទ្យាល័យបច្ចេកវិទ្យា|"
    # Burmese
    r"တက္ကသိုလ်|ကျောင်း|အထက်တန်းကျောင်း|"
    r"အလယ်တန်းကျောင်း|မူလတန်းကျောင်း|"
    r"နည်းပညာတက္ကသိုလ်|"
    # Lao
    r"ມະຫາວິທະຍາໄລ|ໂຮງຮຽນ|ວິທະຍາໄລ|"
    r"ໂຮງຮຽນມັດທະຍົມ|ໂຮງຮຽນປະຖົມ|"
    # Nepali
    r"विश्वविद्यालय|विद्यालय|कलेज|"
    r"माध्यमिक विद्यालय|प्राथमिक विद्यालय|"
    r"प्राविधिक विश्वविद्यालय|"
    # Sinhala
    r"විශ්වවිද්‍යාලය|පාසල|විදුහල|"
    r"උසස් පාසල|ද්වීතීයික පාසල|"
    # Amharic
    r"ዩኒቨርሲቲ|ትምህርት ቤት|ኮሌጅ|"
    r"ሁለተኛ ደረጃ ትምህርት ቤት|መሰናዶ ትምህርት ቤት|"
    # Yoruba
    r"yunifásítì|ilé ìwé|kọ́léèjì|"
    r"ilé ìwé gíga|ilé ìwé alákọ̀ọ́bẹ̀rẹ̀|"
    # Hausa
    r"jami'a|makaranta|kwaleji|"
    r"makarantar sakandare|makarantar firamare|"
    # Igbo
    r"mahadum|ụlọ akwụkwọ|kọleji|"
    r"ụlọ akwụkwọ sekọndrị|ụlọ akwụkwọ praịmrị|"
    # Zulu
    r"inyuvesi|isikole|ikholishi|"
    r"isikole samabanga aphezulu|isikole samabanga aphansi|"
    r"isikhungo semfundo|"
    # Pashto
    r"پوهنتون|ښوونځی|کالج|"
    r"لومړنی ښوونځی|منځنی ښوونځی|"
    r"تخنیکي پوهنتون|"
    # Kurdish
    r"zanîngeh|dibistan|kolêj|"
    r"dibistana navîn|dibistana seretayî|"
    r"zanîngeha teknîkî|enstîtuya polîteknîk|"
    # Tajik
    r"донишгоҳ|мактаб|коллеҷ|"
    r"мактаби миёна|мактаби ибтидоӣ|"
    r"донишгоҳи техникӣ|"
    # Kyrgyz
    r"университет|мектеп|колледж|"
    r"орто мектеп|башталгыч мектеп|"
    # Maltese
    r"università|skola|kulleġġ|"
    r"skola sekondarja|skola primarja|"
    r"università teknika|"
    # Luxembourgish
    r"universitéit|schoul|kolleg|"
    r"lycée|lycée technique|grondschoul|"
    # Haitian Creole
    r"inivèsite|lekòl|kolèj|"
    r"lise|lekòl segondè|lekòl primè|"
    # Frisian
    r"universiteit|skoalle|kolleezje|"
    r"middelskoalle|basisskoalle|technyske universiteit|"
    # Yiddish
    r"אוניווערסיטעט|שולע|קאלעדזש|"
    r"מיטל שולע|גרונט שולע|"
    # Faroese
    r"háskúli|skúli|hægri skúli|"
    # Tatar
    r"университет|мәктәп|урта мәктәп|"
    # Javanese
    r"universitas|sekolah|sekolah menengah|"
    # Sundanese
    r"universitas|sakola|"
    # Cebuano
    r"unibersidad|eskwelahan|kolehiyo|"
    r"hayskul|elementarya"
    r")\b"
)

GOV_RE = re.compile(
    r"(?i)\b("
    # English
    r"government of|state of|county of|city of|"
    r"ministry of|department of|bureau of|agency of|"
    r"municipal government|municipality of|"
    r"federal government|state government|local government|"
    r"office of the (?:president|prime minister|governor|mayor|attorney|"
    r"secretary)|"
    r"\.gov\.|public sector|civil service|"
    # Spanish
    r"ministerio de|gobierno de|alcaldía|ayuntamiento|municipio de|"
    r"departamento de gobierno|prefectura de|"
    r"administración pública|secretaría de|"
    # Portuguese
    r"ministério de|governo de|prefeitura de|câmara municipal|"
    r"administração pública|secretaria de|"
    # French
    r"ministère de|gouvernement de|mairie de|préfecture de|"
    r"administration publique|secrétariat de|"
    # Italian
    r"ministero (?:di|della)|governo della|comune di|prefettura di|"
    r"amministrazione pubblica|"
    # German
    r"bundesregierung|landesregierung|stadtverwaltung|"
    r"gemeindeverwaltung|ministerium für|behörde|rathaus|"
    # Dutch
    r"regering|ministerie|gemeentebestuur|"
    # Polish
    r"rząd|ministerstwo|urząd miasta|administracja publiczna|"
    # Czech
    r"vláda|ministerstvo|magistrát|radnice|"
    # Slovak
    r"vláda|ministerstvo|magistrát|"
    # Croatian / Serbian / Bosnian
    r"vlada|ministarstvo|opština|grad uprava|"
    # Slovenian
    r"vlada|ministrstvo|občina|"
    # Romanian
    r"guvernul|ministerul|primăria|"
    # Hungarian
    r"kormány|minisztérium|polgármesteri hivatal|"
    # Bulgarian
    r"правителство|министерство|община|"
    # Russian
    r"правительство|министерство|администрация|мэрия|"
    r"государственное учреждение|"
    # Ukrainian
    r"уряд|міністерство|адміністрація|"
    # Turkish
    r"hükümeti|bakanlığı|belediyesi|kamu kurumu|"
    # Greek
    r"κυβέρνηση|υπουργείο|δήμος|δημόσιος τομέας|"
    # Albanian
    r"qeveria|ministria|"
    # Arabic
    r"حكومة|وزارة|بلدية|دائرة حكومية|"
    # Hebrew
    r"ממשלה|משרד|עירייה|רשות מקומית|"
    # Persian (Farsi)
    r"دولت|وزارت|شهرداری|"
    # Urdu
    r"حکومت|وزارت|"
    # Hindi
    r"सरकार|मंत्रालय|नगर निगम|"
    # Bengali
    r"সরকার|মন্ত্রণালয়|"
    # Tamil
    r"அரசு|அமைச்சகம்|"
    # Telugu
    r"ప్రభుత్వం|మంత్రిత్వ శాఖ|"
    # Marathi
    r"सरकार|मंत्रालय|"
    # Gujarati
    r"સરકાર|"
    # Punjabi
    r"ਸਰਕਾਰ|"
    # Chinese (Simplified and Traditional)
    r"政府|部委|市政府|国务院|縣政府|县政府|"
    # Japanese
    r"せいふ|内閣府|市役所|県庁|"
    # Korean
    r"정부|시청|군청|도청|국무총리실|"
    # Vietnamese
    r"chính phủ|bộ|ủy ban nhân dân|"
    # Thai
    r"รัฐบาล|กระทรวง|เทศบาล|"
    # Indonesian
    r"pemerintah|kementerian|walikota|"
    # Malay
    r"kerajaan|kementerian|majlis daerah|"
    # Filipino (Tagalog)
    r"pamahalaan|kagawaran|"
    # Swahili
    r"serikali|wizara|"
    # Swedish
    r"regering|departement|kommunfullmäktige|"
    # Norwegian
    r"regjering|departement|kommunestyre|"
    # Danish
    r"regering|ministerium|kommune|"
    # Finnish
    r"hallitus|ministeriö|kaupunginvaltuusto|"
    # Icelandic
    r"ríkisstjórn|ráðuneyti|sveitarfélag|"
    # Estonian
    r"valitsus|ministeerium|linnavalitsus|"
    # Latvian
    r"valdība|ministrija|pašvaldība|"
    # Lithuanian
    r"vyriausybė|ministerija|savivaldybė|"
    # Catalan
    r"govern|ministeri|ajuntament|"
    # Basque
    r"gobernua|"
    # Galician
    r"goberno|concello|"
    # Welsh
    r"llywodraeth|"
    # Irish
    r"rialtas|aireacht|"
    # Afrikaans
    r"regering|departement|"
    # Macedonian
    r"влада|министерство|општина|"
    r"градска управа|јавен сектор|"
    r"државна институција|секретаријат|"
    # Belarusian
    r"урад|міністэрства|"
    r"гарадская адміністрацыя|дзяржаўная ўстанова|"
    r"мясцовае самакіраванне|"
    # Azerbaijani
    r"hökumət|nazirlik|bələdiyyə|"
    r"şəhər icra hakimiyyəti|dövlət qurumu|"
    r"katiblik|ictimai sektor|"
    # Georgian
    r"მთავრობა|სამინისტრო|მერია|"
    r"მუნიციპალიტეტი|საჯარო სექტორი|"
    r"სახელმწიფო დაწესებულება|"
    # Armenian
    r"կառավարություն|նախարարություն|քաղաքապետարան|"
    r"մունիցիպալիտետ|հանրային ոլորտ|"
    r"պետական հաստատություն|"
    # Kazakh
    r"үкімет|министрлік|әкімдік|"
    r"қалалық әкімшілік|мемлекеттік мекеме|"
    r"жергілікті өзін[- ]өзі басқару|"
    # Uzbek
    r"hukumat|vazirlik|hokimiyat|"
    r"shahar hokimiyati|davlat muassasasi|"
    r"mahalliy o'zini o'zi boshqarish|"
    # Mongolian
    r"засгийн газар|яам|"
    r"хотын захиргаа|төрийн байгууллага|"
    r"орон нутгийн засаг захиргаа|"
    # Khmer
    r"រដ្ឋាភិបាល|ក្រសួង|សាលាក្រុង|"
    r"រដ្ឋបាល|អង្គភាពរដ្ឋ|វិស័យសាធារណៈ|"
    # Burmese
    r"အစိုးရ|ဝန်ကြီးဌာန|"
    r"မြို့တော် စည်ပင်သာယာရေး|အစိုးရအဖွဲ့အစည်း|"
    r"ပြည်နယ်အစိုးရ|ပြည်ထောင်စုအစိုးရ|"
    # Lao
    r"ລັດຖະບານ|ກະຊວງ|"
    r"ອົງການປົກຄອງ|ອົງການລັດ|"
    # Nepali
    r"सरकार|मन्त्रालय|"
    r"नगरपालिका|सरकारी निकाय|"
    r"सार्वजनिक क्षेत्र|"
    # Sinhala
    r"රජය|අමාත්‍යාංශය|"
    r"නගර සභාව|රජයේ ආයතනය|"
    r"පළාත් පාලන ආයතනය|"
    # Amharic
    r"መንግሥት|ሚኒስቴር|"
    r"ማዘጋጃ ቤት|መስተዳድር|"
    # Yoruba
    r"ìjọba|ilé ìjọba|ẹ̀ka ìjọba|"
    r"ìjọba ìbílẹ̀|ilé ọ̀dọ̀mọdé ìjọba|"
    # Hausa
    r"gwamnati|ma'aikatar|"
    r"ƙaramar hukuma|hukumar gudanarwa|"
    # Igbo
    r"gọọmenti|ngalaba gọọmenti|"
    r"ọchịchị obodo|"
    # Zulu
    r"uhulumeni|umnyango|"
    r"umasipala|umkhandlu wedolobha|"
    r"isikhungo sikahulumeni|"
    # Pashto
    r"حکومت|وزارت|شاروالۍ|"
    r"ښار والی|عامه څانگه|دولتي اداره|"
    # Kurdish
    r"hikûmet|wezaret|şaredarî|"
    r"rêveberî|sazî dewletî|sektora giştî|"
    # Tajik
    r"ҳукумат|вазорат|"
    r"мақомоти иҷроия|муассисаи давлатӣ|"
    # Kyrgyz
    r"өкмөт|министрлик|"
    r"мэрия|мамлекеттик мекеме|"
    # Maltese
    r"gvern|ministeru|kunsill lokali|"
    r"awtorità lokali|servizz pubbliku|"
    r"dipartiment tal-gvern|"
    # Luxembourgish
    r"regierung|ministère|gemeng|"
    r"administratioun|öffentlech verwaltung|"
    r"staatlech institutioun|"
    # Haitian Creole
    r"gouvènman|ministè|"
    r"meri|administrasyon piblik|"
    r"enstitisyon leta|"
    # Frisian
    r"oerheid|gemeente|"
    r"ministearje|oerheidsynstânsje|"
    # Yiddish
    r"רעגירונג|מיניסטעריום|"
    r"שטאט פארוואלטונג|"
    # Faroese
    r"stjórn|ráðharrastýri|"
    r"kommuna|fólkavald|"
    # Tatar
    r"хөкүмәт|министрлык|"
    r"шәһәр администрациясе|дәүләт оешмасы|"
    # Javanese
    r"pamarintahan|kabupaten|"
    r"kotamadya|kementerian|"
    # Sundanese
    r"pamaréntahan|kotamadya|"
    # Cebuano
    r"gobyerno|munisipyo|"
    r"kagawaran|departamento sa gobyerno"
    r")\b"
)

HEALTHCARE_RE = re.compile(
    r"(?i)\b("
    # English
    r"hospital|medical center|medical centre|medical clinic|"
    r"healthcare|health system|health network|health care|"
    r"pharmaceutical|pharmacy|pharmaceuticals|"
    r"life sciences|biotech|biopharma|biotechnology|"
    r"medical group|physicians group|specialty care|"
    r"long[- ]term care|skilled nursing|aged care|senior care|"
    r"medical practice|nursing home|surgical center|surgical centre|"
    r"diagnostic center|diagnostic centre|outpatient clinic|emergency room|"
    r"medical device|medical equipment|"
    # Spanish
    r"clínica|farmacia|sanidad|centro médico|laboratorio clínico|"
    r"hospital privado|atención médica|consultorio médico|"
    r"servicios sanitarios|cirugía|urgencias|ambulatorio|"
    r"residencia geriátrica|atención sanitaria|industria farmacéutica|"
    # Portuguese
    r"farmácia|saúde|atendimento médico|consultório médico|"
    r"plano de saúde|posto de saúde|laboratório clínico|"
    r"pronto[- ]?socorro|cirurgia|atendimento hospitalar|"
    r"serviços de saúde|indústria farmacêutica|"
    # French
    r"hôpital|clinique|centre médical|cabinet médical|"
    r"pharmacie|laboratoire médical|industrie pharmaceutique|"
    r"soins de santé|établissement de santé|maison de retraite|"
    # Italian
    r"sanità|ospedale|farmacia|laboratorio medico|"
    r"clinica|casa di cura|industria farmaceutica|"
    # German
    r"krankenhaus|klinik|apotheke|arztpraxis|medizinisches zentrum|"
    r"gesundheitswesen|pflegeheim|pharmaindustrie|"
    r"medizintechnik|medizinprodukte|"
    # Dutch
    r"ziekenhuis|apotheek|gezondheidszorg|"
    # Polish
    r"szpital|apteka|przychodnia|opieka zdrowotna|"
    r"przemysł farmaceutyczny|gabinet lekarski|"
    # Czech
    r"nemocnice|lékárna|zdravotnictví|farmaceutický průmysl|"
    r"ordinace|zdravotnické zařízení|"
    # Slovak
    r"nemocnica|lekáreň|zdravotníctvo|"
    # Russian
    r"больница|клиника|поликлиника|аптека|медицинский центр|"
    r"здравоохранение|фармацевтическая компания|медицинский центр|"
    r"стоматология|"
    # Turkish
    r"hastane|sağlık|eczane|sağlık hizmetleri|tıp merkezi|"
    r"ilaç şirketi|"
    # Greek
    r"νοσοκομείο|κλινική|φαρμακείο|κέντρο υγείας|"
    # Chinese (Simplified and Traditional)
    r"医院|医療|診療所|薬局|医疗|健康|医药|醫藥|"
    r"健康产业|健康產業|医学中心|醫學中心|"
    # Japanese (kana plus distinct kanji)
    r"びょういん|やっきょく|医療法人|製薬会社|"
    # Korean
    r"병원|의원|약국|의료서비스|제약회사|"
    # Arabic
    r"مستشفى|عيادة|صيدلية|الرعاية الصحية|"
    # Hebrew
    r"בית חולים|מרפאה|בית מרקחת|"
    # Vietnamese
    r"bệnh viện|phòng khám|nhà thuốc|"
    # Indonesian
    r"rumah sakit|klinik|apotek|"
    # Macedonian
    r"болница|аптека|клиника|медицински центар|"
    r"здравствена заштита|здравство|"
    r"фармацевтска индустрија|дом за стари лица|"
    # Belarusian
    r"бальніца|аптэка|клініка|паліклініка|"
    r"медыцынскі цэнтр|ахова здароўя|"
    r"фармацэўтычная прамысловасць|"
    # Azerbaijani
    r"xəstəxana|aptek|klinika|tibb mərkəzi|"
    r"səhiyyə|səhiyyə xidməti|"
    r"əczaçılıq sənayesi|qocalar evi|"
    # Georgian
    r"საავადმყოფო|აფთიაქი|კლინიკა|პოლიკლინიკა|"
    r"სამედიცინო ცენტრი|ჯანდაცვა|"
    r"ფარმაცევტული მრეწველობა|"
    # Armenian
    r"հիվանդանոց|դեղատուն|կլինիկա|պոլիկլինիկա|"
    r"բժշկական կենտրոն|առողջապահություն|"
    r"դեղագործական արդյունաբերություն|"
    # Kazakh
    r"аурухана|дәріхана|емхана|клиника|"
    r"медициналық орталық|денсаулық сақтау|"
    r"фармацевтикалық өнеркәсіп|қарттар үйі|"
    # Uzbek
    r"shifoxona|kasalxona|dorixona|klinika|poliklinika|"
    r"tibbiyot markazi|sog'liqni saqlash|"
    r"farmatsevtika sanoati|"
    # Mongolian
    r"эмнэлэг|эмийн сан|клиник|поликлиник|"
    r"эмчилгээний төв|эрүүл мэндийн салбар|"
    r"эм үйлдвэрлэл|"
    # Khmer
    r"មន្ទីរពេទ្យ|ឱសថស្ថាន|គ្លីនិក|ពេទ្យឯកជន|"
    r"មជ្ឈមណ្ឌលវេជ្ជសាស្ត្រ|សុខាភិបាល|"
    r"ឧស្សាហកម្មឱសថ|"
    # Burmese
    r"ဆေးရုံ|ဆေးဆိုင်|ဆေးခန်း|"
    r"ဆေးဘက်ဆိုင်ရာ|ကျန်းမာရေး|ဆေးဝါးထုတ်လုပ်မှု|"
    # Lao
    r"ໂຮງໝໍ|ຮ້ານຂາຍຢາ|ຄລີນິກ|"
    r"ສາທາລະນະສຸກ|ການແພດ|"
    # Nepali
    r"अस्पताल|फार्मेसी|औषधि पसल|क्लिनिक|"
    r"चिकित्सा केन्द्र|स्वास्थ्य सेवा|"
    r"औषधि उद्योग|"
    # Sinhala
    r"රෝහල|ෆාමසිය|ඖෂධ ශාලාව|සායනය|"
    r"සෞඛ්‍ය සේවය|ඖෂධ කර්මාන්තය|"
    # Amharic
    r"ሆስፒታል|ፋርማሲ|ክሊኒክ|"
    r"የህክምና ማዕከል|ጤና አገልግሎት|መድሃኒት አምራች|"
    # Yoruba
    r"ilé ìwòsàn|ilé oògùn|ilé ìtọ́jú|"
    r"ìtọ́jú ìlera|iṣẹ́ ìṣègùn|"
    # Hausa
    r"asibiti|kantin magani|kiliniki|"
    r"cibiyar lafiya|kiwon lafiya|kamfanin magunguna|"
    # Igbo
    r"ụlọ ọgwụ|ụlọ ahịa ọgwụ|klinik|"
    r"nlekọta ahụike|ụlọ ọrụ ọgwụ|"
    # Zulu
    r"isibhedlela|ikhemisi|isitolo semithi|umtholampilo|"
    r"ukunakekelwa kwezempilo|imboni yemithi|ezempilo|"
    # Pashto
    r"روغتون|درملتون|کلینیک|"
    r"د درملنې مرکز|روغتیا|د درملو صنعت|"
    # Kurdish
    r"nexweşxane|dermanxane|klînîk|"
    r"navenda derman|tenduristî|pîşesaziya derman|"
    # Tajik
    r"беморхона|дорухона|клиника|поликлиника|"
    r"маркази тиббӣ|тандурустӣ|саноати дорусозӣ|"
    # Kyrgyz
    r"оорукана|дарыкана|клиника|саламаттыкты сактоо|"
    # Maltese
    r"sptar|spiżerija|klinika|ċentru mediku|"
    r"kura tas-saħħa|industrija farmaċewtika|"
    r"dar tal-anzjani|"
    # Luxembourgish
    r"spidol|apdikt|klinik|medizinescht zentrum|"
    r"gesondheetswiesen|pharmaindustrie|"
    r"altersheim|alterswunneng|"
    # Haitian Creole
    r"lopital|famasi|klinik|sant medikal|"
    r"swen sante|endistri famasetik|"
    # Frisian
    r"sikehûs|apteek|kliniek|sûnenssoarch|"
    # Yiddish
    r"שפיטאל|אפטייק|קליניק|מעדישינישע צענטער|"
    # Faroese
    r"sjúkrahús|apotek|heilsustøð|heilsuvern|"
    # Tatar
    r"хастаханә|даруханә|поликлиника|"
    # Javanese
    r"rumah sakit|apotek|klinik|"
    r"puskesmas|pelayanan kesehatan|"
    # Sundanese
    r"rumah sakit|apotek|klinik|"
    # Cebuano
    r"ospital|botika|klinika|sentro medikal"
    r")\b"
)

# Retail / e-commerce — online shop, marketplace, store-style sites.
RETAIL_RE = re.compile(
    r"(?i)\b("
    # Core concepts: online store / e-commerce / retailer / department store /
    # supermarket / shop. Each translated below across major world languages.
    # English
    r"online (?:shop|store)|e[ -]?commerce|"
    r"online marketplace|shopping site|"
    r"retailer|retail (?:store|chain|company|group)|"
    r"buy online|shop now (?:and|to)|"
    r"add to cart|product catalogue|product catalog|"
    r"department store|grocery store|supermarket chain|"
    r"convenience store|specialty retailer|"
    r"trading company|merchant of|"
    # Spanish
    r"tienda online|tienda virtual|tienda departamental|"
    r"comercio electrónico|supermercado|grandes almacenes|"
    r"minorista|cadena de tiendas|"
    # Portuguese
    r"loja online|loja virtual|loja de departamentos|"
    r"comércio eletrônico|supermercado|"
    r"varejista|rede varejista|"
    # French
    r"boutique en ligne|grand magasin|chaîne de magasins|"
    r"commerce en ligne|supermarché|"
    r"détaillant|chaîne de distribution|"
    # Italian
    r"negozio online|grande magazzino|catena di negozi|"
    r"commercio elettronico|supermercato|"
    r"rivenditore|catena di vendita al dettaglio|"
    # German
    r"online[- ]?shop|onlineshop|einzelhändler|fachhändler|"
    r"detailhandel|handelsunternehmen|kaufhaus|supermarkt|"
    r"einzelhandelskette|"
    # Dutch
    r"online winkel|warenhuis|supermarkt|detailhandel|"
    # Polish
    r"sklep internetowy|sklep online|sieć handlowa|supermarket|"
    r"detalista|sieć sklepów|"
    # Czech
    r"obchodní řetězec|internetový obchod|supermarket|"
    r"obchod online|maloobchod|"
    # Slovak
    r"internetový obchod|maloobchod|"
    # Russian
    r"интернет[- ]магазин|онлайн[- ]магазин|"
    r"торговая сеть|розничная сеть|супермаркет|универмаг|"
    r"розничный магазин|"
    # Ukrainian
    r"інтернет[- ]магазин|роздрібна мережа|супермаркет|"
    # Bulgarian
    r"онлайн магазин|супермаркет|търговска верига|"
    # Romanian
    r"magazin online|supermarket|retailer|magazin universal|"
    # Hungarian
    r"online bolt|webáruház|szupermarket|"
    # Greek
    r"ηλεκτρονικό κατάστημα|υπεραγορά|εμπορική αλυσίδα|"
    # Turkish
    r"online mağaza|alışveriş sitesi|perakende zinciri|"
    r"süpermarket|büyük mağaza|"
    # Albanian
    r"dyqan online|supermarket|"
    # Slovenian
    r"spletna trgovina|trgovska veriga|"
    # Croatian / Serbian / Bosnian
    r"online trgovina|trgovačka mreža|trgovački centar|"
    # Estonian
    r"e[- ]pood|kaubandusvõrgustik|"
    # Latvian
    r"interneta veikals|veikalu tīkls|"
    # Lithuanian
    r"internetinė parduotuvė|parduotuvių tinklas|"
    # Finnish
    r"verkkokauppa|tavaratalo|kauppaketju|"
    # Swedish
    r"webbutik|näthandel|varuhus|stormarknad|"
    # Norwegian
    r"nettbutikk|varehus|stormarked|"
    # Danish
    r"netbutik|stormagasin|"
    # Icelandic
    r"netverslun|stórmarkaður|"
    # Persian
    r"فروشگاه اینترنتی|سوپرمارکت|"
    # Urdu
    r"آن لائن سٹور|"
    # Arabic
    r"متجر إلكتروني|متجر على الإنترنت|سوبر ماركت|"
    r"محل تجاري|سلسلة متاجر|"
    # Hebrew
    r"חנות אונליין|חנות מקוונת|רשת קמעונאית|"
    # Hindi
    r"ऑनलाइन स्टोर|सुपरमार्केट|दुकान|"
    # Bengali
    r"অনলাইন স্টোর|"
    # Tamil
    r"ஆன்லைன் கடை|பல்பொருள் அங்காடி|"
    # Telugu
    r"ఆన్‌లైన్ స్టోర్|"
    # Marathi
    r"ऑनलाइन दुकान|"
    # Chinese (Simplified and Traditional)
    r"网上商店|网店|网上购物|电商|電商|百货|百貨|超市|"
    r"零售商|连锁店|連鎖店|"
    # Japanese
    r"オンラインショップ|通販|百貨店|スーパーマーケット|"
    r"小売チェーン|"
    # Korean
    r"온라인 쇼핑|온라인 스토어|쇼핑몰|소매점|체인점|"
    # Vietnamese
    r"cửa hàng trực tuyến|mua sắm online|siêu thị|"
    # Thai
    r"ร้านค้าออนไลน์|ห้างสรรพสินค้า|ซูเปอร์มาร์เก็ต|"
    # Indonesian
    r"toko online|belanja online|supermarket|"
    # Malay
    r"kedai dalam talian|pasaraya|"
    # Filipino (Tagalog)
    r"tindahang online|"
    # Swahili
    r"duka la mtandaoni|"
    # Catalan
    r"botiga en línia|hipermercat|"
    # Galician
    r"tenda en liña|"
    # Basque
    r"online denda|supermerkatu|"
    # Welsh
    r"siop ar-lein|"
    # Irish
    r"siopa ar líne|"
    # Afrikaans
    r"aanlyn winkel|"
    # Esperanto
    r"reta vendejo|"
    # Macedonian
    r"онлајн продавница|интернет продавница|"
    r"е-трговија|трговски синџир|супермаркет|"
    r"стоковна куќа|продажба на мало|"
    # Belarusian
    r"інтэрнэт-крама|анлайн крама|"
    r"электронная камерцыя|гандлёвая сетка|супермаркет|"
    r"роздробны магазін|"
    # Azerbaijani
    r"onlayn mağaza|internet mağaza|"
    r"elektron ticarət|ticarət şəbəkəsi|supermarket|"
    r"univermaq|pərakəndə satış|"
    # Georgian
    r"ონლაინ მაღაზია|ინტერნეტ მაღაზია|"
    r"ელექტრონული კომერცია|სავაჭრო ქსელი|სუპერმარკეტი|"
    r"უნივერმაღი|საცალო ვაჭრობა|"
    # Armenian
    r"առցանց խանութ|ինտերնետ խանութ|"
    r"էլեկտրոնային առևտուր|առևտրի ցանց|սուպերմարկետ|"
    r"հանրախանութ|մանրածախ առևտուր|"
    # Kazakh
    r"онлайн дүкен|интернет дүкен|"
    r"электрондық сауда|сауда желісі|супермаркет|"
    r"универмаг|бөлшек сауда|"
    # Uzbek
    r"onlayn do'kon|internet do'kon|"
    r"elektron tijorat|savdo tarmog'i|supermarket|"
    r"chakana savdo|"
    # Mongolian
    r"онлайн дэлгүүр|интернет дэлгүүр|"
    r"цахим худалдаа|худалдааны сүлжээ|супермаркет|"
    r"их дэлгүүр|жижиглэн худалдаа|"
    # Khmer
    r"ហាងអនឡាញ|ហាងលើបណ្តាញ|"
    r"ពាណិជ្ជកម្មអេឡិចត្រូនិក|បណ្តាញហាង|សុបមាក|"
    # Burmese
    r"အွန်လိုင်းဆိုင်|အင်တာနက်ဆိုင်|"
    r"အီလက်ထရောနစ်ကုန်သွယ်ရေး|"
    r"စူပါမားကတ်|လက်လီရောင်းဝယ်ရေး|"
    # Lao
    r"ຮ້ານອອນລາຍ|ຮ້ານອິນເຕີເນັດ|"
    r"ການຄ້າອອນລາຍ|ຮ້ານສະດວກຊື້|"
    r"ສະຖານທີ່ຂາຍຍ່ອຍ|"
    # Nepali
    r"अनलाइन स्टोर|इन्टरनेट स्टोर|"
    r"इ-कमर्स|खुद्रा पसल|सुपरमार्केट|"
    r"डिपार्टमेन्टल स्टोर|"
    # Sinhala
    r"ඔන්ලයින් වෙළඳසැල|අන්තර්ජාල වෙළඳසැල|"
    r"ඉ-වාණිජ්‍යය|සුපිරි වෙළඳසැල|"
    r"සිල්ලර වෙළඳසැල|"
    # Amharic
    r"የመስመር ላይ ሱቅ|የኢንተርኔት ሱቅ|"
    r"ኢ-ኮሜርስ|ሱፐርማርኬት|"
    r"የችርቻሮ ሱቅ|"
    # Yoruba
    r"ilé ọjà orí ayélujára|"
    r"ìṣòwò orí ayélujára|sòpù ńlá|"
    r"ọjà ìpèsè|"
    # Hausa
    r"shagon kan layi|kasuwar lantarki|"
    r"e-kasuwanci|babban kanti|"
    r"shago na ƙarami|"
    # Igbo
    r"ụlọ ahịa intanetị|ụlọ ahịa n'ịntanet|"
    r"azụmaahịa elektrọnịkị|ụlọ ahịa ukwu|"
    # Zulu
    r"isitolo se-online|isitolo se-internet|"
    r"i-e-commerce|i-supermarket|"
    r"isitolo sokugcwele|"
    # Pashto
    r"آنلاین پلورنځی|د انټرنیټ پلورنځی|"
    r"الکترونیکي سوداگري|سوپرمارکیټ|"
    r"د پرچون پلورنځی|"
    # Kurdish
    r"firotgeha online|firotgeha torê|"
    r"bazirganiya elektronîk|supermarket|"
    r"firotgeha hûrebir|"
    # Tajik
    r"мағозаи онлайн|мағозаи интернетӣ|"
    r"тиҷорати электронӣ|супермаркет|"
    r"мағозаи чакана|"
    # Kyrgyz
    r"онлайн дүкөн|интернет дүкөн|"
    r"электрондук соода|супермаркет|"
    r"чекене соода|"
    # Maltese
    r"ħanut online|ħanut tal-internet|"
    r"kummerċ elettroniku|supermarket|"
    r"katina ta' ħwienet|bejgħ bl-imnut|"
    # Luxembourgish
    r"online buttek|internet buttek|"
    r"e-handel|supermarché|kafhaus|"
    r"detailhandel|"
    # Haitian Creole
    r"magazen sou entènèt|boutik anliy|"
    r"e-komès|supermache|"
    r"vant an detay|"
    # Frisian
    r"online winkel|webwinkel|"
    r"e-hannel|supermerk|"
    # Yiddish
    r"אָנליין געשעפט|"
    r"סופערמאַרק|"
    # Faroese
    r"online handil|stórmarknað|"
    # Tatar
    r"онлайн кибет|интернет-кибет|"
    r"электрон сату|супермаркет|"
    # Javanese
    r"toko online|toko internet|"
    r"e-dagang|supermarket|"
    # Sundanese
    r"toko online|"
    # Cebuano
    r"online nga tindahan|tindahan sa internet|"
    r"e-commerce|supermarket|"
    r"tindahan sa retail"
    r")\b"
)

# Manufacturing / industrial — factories, OEMs, equipment makers
MANUFACTURING_RE = re.compile(
    r"(?i)\b("
    # English
    r"manufacturer|manufacturing|factory|"
    r"industrial equipment|production plant|production line|"
    r"original equipment manufacturer|\boem\b|"
    r"steel mill|chemical plant|"
    r"automotive supplier|component supplier|contract manufacturer|"
    r"manufacturing plant|manufacturing facility|"
    # Spanish
    r"fabricación|fabricante|fábrica|empresa manufacturera|manufacturera|"
    r"planta de producción|línea de producción|"
    r"equipo industrial|proveedor de componentes|"
    r"fabricante por contrato|planta industrial|"
    # Portuguese
    r"fabricação|fábrica|fabricante|"
    r"planta de produção|linha de produção|"
    r"equipamento industrial|fornecedor de componentes|"
    r"fabricante por contrato|"
    # French
    r"fabricant|usine|industrie manufacturière|"
    r"site de production|chaîne de production|"
    r"équipement industriel|fournisseur de composants|"
    r"fabricant sous contrat|"
    # Italian
    r"fabbricazione|costruttore|stabilimento produttivo|manufactura|"
    r"impianto di produzione|linea di produzione|"
    r"attrezzature industriali|fornitore di componenti|"
    # German
    r"hersteller|fabrik|produktionsstätte|industriebetrieb|"
    r"produktionsanlage|fertigungslinie|"
    r"industrieausrüstung|komponentenhersteller|"
    r"auftragsfertigung|automobilzulieferer|"
    # Dutch
    r"fabrikant|productiebedrijf|"
    r"productie-installatie|productielijn|"
    r"industriële uitrusting|onderdelenleverancier|"
    # Polish
    r"producent|wytwórca|fabryka|"
    r"zakład produkcyjny|linia produkcyjna|"
    r"sprzęt przemysłowy|dostawca komponentów|"
    r"producent kontraktowy|"
    # Czech
    r"výrobce|závod|továrna|"
    r"výrobní závod|výrobní linka|"
    r"průmyslové vybavení|dodavatel komponentů|"
    # Slovak
    r"výrobca|továreň|"
    r"výrobný závod|priemyselné vybavenie|"
    # Russian
    r"производитель|завод|фабрика|"
    r"производственное предприятие|производственная линия|"
    r"промышленное оборудование|поставщик компонентов|"
    r"контрактный производитель|металлургический комбинат|"
    # Ukrainian
    r"виробник|завод|фабрика|"
    r"виробниче підприємство|металургійний комбінат|"
    # Bulgarian
    r"производител|фабрика|завод|"
    r"производствено предприятие|"
    # Romanian
    r"producător|fabrică|"
    r"unitate de producție|linie de producție|"
    r"echipamente industriale|"
    # Hungarian
    r"gyártó|gyár|"
    r"gyártóüzem|gyártósor|"
    r"ipari berendezés|alkatrész beszállító|"
    r"bérgyártó|"
    # Greek
    r"κατασκευαστής|βιομηχανία|εργοστάσιο|"
    r"μονάδα παραγωγής|γραμμή παραγωγής|"
    r"βιομηχανικός εξοπλισμός|προμηθευτής εξαρτημάτων|"
    # Turkish
    r"üretici|imalatçı|fabrika|"
    r"üretim tesisi|üretim hattı|"
    r"endüstriyel ekipman|bileşen tedarikçisi|"
    r"sözleşmeli üretici|"
    # Albanian
    r"prodhues|fabrikë|impiant prodhimi|"
    # Croatian / Serbian / Bosnian
    r"proizvođač|fabrika|tvornica|"
    r"proizvodni pogon|proizvodna linija|"
    r"industrijska oprema|"
    # Slovenian
    r"proizvajalec|tovarna|"
    r"proizvodni obrat|proizvodna linija|"
    r"industrijska oprema|"
    # Estonian
    r"tootja|tehas|"
    r"tootmistehas|tootmisliin|"
    r"tööstusseadmed|"
    # Latvian
    r"ražotājs|rūpnīca|"
    r"ražošanas uzņēmums|ražošanas līnija|"
    r"rūpnieciskais aprīkojums|"
    # Lithuanian
    r"gamintojas|gamykla|"
    r"gamybos įmonė|gamybos linija|"
    r"pramoninė įranga|"
    # Finnish
    r"valmistaja|tehdas|"
    r"tuotantolaitos|tuotantolinja|"
    r"teollisuuslaitteet|alihankkija|"
    # Swedish
    r"tillverkare|fabrik|"
    r"produktionsanläggning|produktionslinje|"
    r"industriutrustning|underleverantör|"
    # Norwegian
    r"produsent|fabrikk|"
    r"produksjonsanlegg|produksjonslinje|"
    r"industrielt utstyr|underleverandør|"
    # Danish
    r"producent|fabrik|"
    r"produktionsanlæg|produktionslinje|"
    r"industrielt udstyr|underleverandør|"
    # Icelandic
    r"framleiðandi|verksmiðja|"
    # Persian
    r"تولید کننده|کارخانه|"
    r"خط تولید|تجهیزات صنعتی|تامین کننده قطعات|"
    # Urdu
    r"تیار کنندہ|"
    # Arabic
    r"شركة تصنيع|مصنع|الصناعة التحويلية|"
    r"خط إنتاج|معدات صناعية|مورد قطع غيار|"
    r"مصنع للصناعات المعدنية|"
    # Hebrew
    r"יצרן|מפעל|"
    r"מתקן ייצור|קו ייצור|"
    r"ציוד תעשייתי|ספק רכיבים|"
    # Hindi
    r"निर्माता|कारखाना|उत्पादन|"
    r"उत्पादन संयंत्र|"
    # Bengali
    r"প্রস্তুতকারক|কারখানা|উৎপাদন|"
    # Tamil
    r"தயாரிப்பாளர்|தொழிற்சாலை|உற்பத்தித் தொழிற்சாலை|"
    # Telugu
    r"తయారీదారు|ఫ్యాక్టరీ|"
    # Marathi
    r"उत्पादक|कारखाना|"
    # Chinese (Simplified and Traditional)
    r"制造商|製造商|工厂|工廠|生产厂|生產廠|生产商|生產商|"
    r"生产基地|生產基地|生产线|生產線|"
    r"工业设备|工業設備|"
    # Japanese
    r"製造業者|工場|"
    r"製造業|製造拠点|生産ライン|"
    r"産業機器|部品サプライヤー|"
    # Korean
    r"제조업체|제조사|공장|"
    r"제조 시설|생산 라인|"
    r"산업 장비|부품 공급업체|"
    # Vietnamese
    r"nhà sản xuất|nhà máy|"
    r"cơ sở sản xuất|dây chuyền sản xuất|"
    r"thiết bị công nghiệp|nhà cung cấp linh kiện|"
    # Thai
    r"ผู้ผลิต|โรงงาน|"
    r"โรงงานผลิต|สายการผลิต|"
    r"อุปกรณ์อุตสาหกรรม|"
    # Indonesian
    r"produsen|pabrik|"
    r"pabrik produksi|jalur produksi|"
    r"peralatan industri|pemasok komponen|"
    # Malay
    r"pengeluar|kilang|"
    r"kilang pengeluaran|barisan pengeluaran|"
    r"peralatan perindustrian|"
    # Filipino (Tagalog)
    r"tagagawa|pabrika|"
    # Swahili
    r"mtengenezaji|kiwanda|"
    # Catalan
    r"fabricant|fàbrica|"
    r"planta de producció|línia de producció|"
    # Galician
    r"fabricante|fábrica|"
    # Welsh
    r"gwneuthurwr|ffatri|"
    # Irish
    r"déantóir|monarcha|"
    # Afrikaans
    r"vervaardiger|fabriek|"
    # Macedonian
    r"производител|фабрика|"
    r"производствен погон|производствена линија|"
    r"индустриска опрема|добавувач на компоненти|"
    # Belarusian
    r"вытворца|фабрыка|"
    r"вытворчае прадпрыемства|вытворчая лінія|"
    r"прамысловае абсталяванне|"
    # Azerbaijani
    r"istehsalçı|fabrik|zavod|"
    r"istehsal müəssisəsi|istehsalat xətti|"
    r"sənaye avadanlığı|komponent təchizatçısı|"
    # Georgian
    r"მწარმოებელი|ქარხანა|"
    r"საწარმო|საწარმოო ხაზი|"
    r"სამრეწველო აღჭურვილობა|"
    # Armenian
    r"արտադրող|գործարան|"
    r"արտադրական ձեռնարկություն|արտադրական գիծ|"
    r"արդյունաբերական սարքավորում|"
    # Kazakh
    r"өндіруші|зауыт|фабрика|"
    r"өндірістік кәсіпорын|өндіріс желісі|"
    r"өндірістік жабдық|"
    # Uzbek
    r"ishlab chiqaruvchi|zavod|fabrika|"
    r"ishlab chiqarish korxonasi|ishlab chiqarish liniyasi|"
    r"sanoat uskunasi|"
    # Mongolian
    r"үйлдвэрлэгч|үйлдвэр|"
    r"үйлдвэрлэлийн аж ахуйн нэгж|үйлдвэрлэлийн шугам|"
    r"аж үйлдвэрийн тоног төхөөрөмж|"
    # Khmer
    r"ក្រុមហ៊ុនផលិត|រោងចក្រ|"
    r"មូលដ្ឋានផលិតកម្ម|បន្ទាត់ផលិតកម្ម|"
    r"ឧបករណ៍ឧស្សាហកម្ម|"
    # Burmese
    r"ထုတ်လုပ်သူ|စက်ရုံ|"
    r"ထုတ်လုပ်ရေး အခြေခံ|ထုတ်လုပ်ရေးလိုင်း|"
    r"စက်မှုဆိုင်ရာ ပစ္စည်းကိရိယာ|"
    # Lao
    r"ຜູ້ຜະລິດ|ໂຮງງານ|"
    r"ໂຮງງານຜະລິດ|ສາຍການຜະລິດ|"
    r"ອຸປະກອນອຸດສາຫະກໍາ|"
    # Nepali
    r"उत्पादक|कारखाना|"
    r"उत्पादन संयन्त्र|उत्पादन रेखा|"
    r"औद्योगिक उपकरण|"
    # Sinhala
    r"නිෂ්පාදකයා|කර්මාන්තශාලාව|"
    r"නිෂ්පාදන මධ්‍යස්ථානය|නිෂ්පාදන රේඛාව|"
    r"කාර්මික උපකරණ|"
    # Amharic
    r"አምራች|ፋብሪካ|"
    r"የምርት ፋብሪካ|የምርት መስመር|"
    # Yoruba
    r"olùṣe ohun|ilé iṣẹ́|"
    r"ilé iṣẹ́ ìmúrasílẹ̀|ìlà ìmúrasílẹ̀|"
    # Hausa
    r"masana'anta|kamfanin samar da kayayyaki|"
    r"masana'antar samar da kayayyaki|"
    r"kayan aikin masana'antu|"
    # Igbo
    r"onye nrụpụta|ụlọ ọrụ nrụpụta|"
    r"ngwa ụlọ ọrụ|"
    # Zulu
    r"umkhiqizi|imboni|ifekthri|"
    r"isikhungo sokukhiqiza|"
    r"izinto ezikhiqizwa imboni|"
    # Pashto
    r"تولیدوونکی|فابریکه|"
    r"د تولید مرکز|د تولید کرښه|"
    r"صنعتي وسایل|"
    # Kurdish
    r"hilberîner|kargeh|"
    r"navenda hilberînê|xeta hilberînê|"
    r"alavên pîşesazî|"
    # Tajik
    r"истеҳсолкунанда|корхона|фабрика|"
    r"корхонаи истеҳсолӣ|хатти истеҳсолӣ|"
    r"таҷҳизоти саноатӣ|"
    # Kyrgyz
    r"өндүрүүчү|завод|фабрика|"
    r"өндүрүш ишканасы|өндүрүш линиясы|"
    # Maltese
    r"manifattur|fabbrika|"
    r"impjant ta' produzzjoni|linja ta' produzzjoni|"
    r"tagħmir industrijali|"
    # Luxembourgish
    r"hiersteller|fabrik|produktiounsanlag|"
    r"produktiounslinn|industriell ausrüstung|"
    # Haitian Creole
    r"manifakti|izin|"
    r"liy pwodiksyon|ekipman endistriyel|"
    # Frisian
    r"fabrikant|fabryk|"
    r"produksjebedriuw|produksjelinear|"
    # Yiddish
    r"פאַבריקאַנט|פאַבריק|"
    r"פּראָדוקציע אנלאַגע|"
    # Faroese
    r"framleiðari|verksmiðja|"
    r"framleiðsluskeið|"
    # Tatar
    r"җитештерүче|фабрика|"
    r"җитештерү линиясе|"
    # Javanese
    r"produsen|pabrik|"
    r"jalur produksi|peralatan industri|"
    # Sundanese
    r"produsén|pabrik|"
    # Cebuano
    r"prodyuser|pabrika|"
    r"pasilidad sa produksyon|kagamitang industriyal"
    r")\b"
)

# Travel / hospitality — hotels, airlines, tourism, travel agencies.
# Maps to the README's "Travel" type per AGENTS.md precedence.
TRAVEL_RE = re.compile(
    r"(?i)\b("
    # English
    r"hotel|resort|inn|hostel|motel|bed and breakfast|"
    r"airline|airways|aviation services|airport authority|"
    r"travel agency|tourism|tour operator|tour company|"
    r"book your stay|book a (?:room|hotel|flight)|"
    r"holiday rental|vacation rental|cruise line|cruise operator|"
    r"casino resort|integrated resort|destination management|"
    r"car rental|travel booking|holiday packages|"
    # Spanish
    r"complejo turístico|agencia de viajes|operador turístico|"
    r"hotel boutique|hostal|albergue|alquiler vacacional|"
    r"compañía aérea|línea aérea|crucero|"
    # Portuguese
    r"agência de viagens|operadora turística|"
    r"hotel|pousada|albergue|aluguel de temporada|"
    r"companhia aérea|linha aérea|cruzeiro|"
    # French
    r"hôtel|hôtellerie|complexe touristique|"
    r"agence de voyage|tourisme|opérateur touristique|"
    r"compagnie aérienne|location de vacances|croisière|gîte|"
    # Italian
    r"albergo|agenzia di viaggi|operatore turistico|turismo|"
    r"compagnia aerea|crociera|villaggio turistico|"
    r"affittacamere|"
    # German
    r"reiseveranstalter|reisebüro|tourismusbüro|"
    r"fluggesellschaft|hotelkette|ferienwohnung|kreuzfahrtgesellschaft|"
    # Dutch
    r"reisbureau|reisorganisator|hotelketen|"
    # Russian
    r"гостиница|отель|туристическое агентство|туризм|туроператор|"
    r"авиакомпания|круиз|курортный комплекс|апартаменты|"
    # Polish
    r"biuro podróży|turystyka|hotel|linia lotnicza|"
    r"wynajem wakacyjny|"
    # Czech
    r"cestovní kancelář|cestovní ruch|hotel|letecká společnost|"
    # Slovak
    r"cestovná kancelária|hotel|"
    # Turkish
    r"otel|seyahat acentesi|turizm şirketi|havayolu şirketi|"
    r"tatil köyü|"
    # Greek
    r"ξενοδοχείο|τουρισμός|αεροπορική εταιρεία|"
    # Chinese (Simplified and Traditional)
    r"酒店|飯店|旅游|旅遊|旅行社|度假村|"
    r"航空公司|郵輪|邮轮|"
    # Korean
    r"호텔|관광|여행사|리조트|항공사|크루즈|"
    # Japanese
    r"ホテル|旅行代理店|観光|航空会社|クルーズ|"
    r"観光地|"
    # Arabic
    r"فندق|سياحة|وكالة سفر|شركة طيران|"
    # Hebrew
    r"מלון|תיירות|חברת תעופה|"
    # Hindi
    r"होटल|पर्यटन|"
    # Vietnamese
    r"khách sạn|du lịch|đại lý du lịch|hãng hàng không|"
    # Indonesian
    r"hotel|biro perjalanan|maskapai penerbangan|"
    # Macedonian
    r"хотел|туризам|туристичка агенција|авиокомпанија|"
    r"мотел|хостел|курорт|туроператор|"
    r"крстарење|изнајмување коли|"
    # Belarusian
    r"гасцініца|турызм|турыстычнае агенцтва|"
    r"матэль|хостэл|курорт|тураператар|"
    r"авіякампанія|круіз|пракат аўтамабіляў|"
    # Azerbaijani
    r"otel|turizm|səyahət agentliyi|hava yolu şirkəti|"
    r"motel|xostel|kurort|tur operatoru|"
    r"kruiz|avtomobil icarəsi|"
    # Georgian
    r"სასტუმრო|ტურიზმი|ტურისტული სააგენტო|ავიაკომპანია|"
    r"მოტელი|ჰოსტელი|კურორტი|ტუროპერატორი|"
    r"კრუიზი|ავტომობილის ქირაობა|"
    # Armenian
    r"հյուրանոց|զբոսաշրջություն|ճանապարհորդական գործակալություն|"
    r"ավիաընկերություն|մոթել|հոսթել|հանգստավայր|"
    r"տուր օպերատոր|նավաշրջագայություն|մեքենայի վարձույթ|"
    # Kazakh
    r"қонақ үй|туризм|турагенттік|әуежай|әуе компаниясы|"
    r"мотель|хостел|курорт|туроператор|"
    r"круиз|автокөлік жалға беру|"
    # Uzbek
    r"mehmonxona|turizm|sayohat agentligi|aviakompaniya|"
    r"motel|xostel|kurort|tur operatori|"
    r"kruiz|avtomobil ijarasi|"
    # Mongolian
    r"зочид буудал|аялал жуулчлал|"
    r"аялалын агентлаг|агаарын тээврийн компани|"
    r"мотель|хостел|амралтын газар|"
    r"круиз|машин түрээслүүлэх|"
    # Khmer
    r"សណ្ឋាគារ|ទេសចរណ៍|ភ្នាក់ងារទេសចរណ៍|"
    r"ម៉ូតែល|ហូស្តែល|រ៉េសត|"
    r"ក្រុមហ៊ុនអាកាសចរណ៍|កប៉ាល់ទេសចរណ៍|ជួលឡាន|"
    # Burmese
    r"ဟိုတယ်|ခရီးသွားလုပ်ငန်း|လေကြောင်းလိုင်း|"
    r"အပန်းဖြေစခန်း|ခရီးစဉ်စီစဉ်ရေး|"
    r"သင်္ဘောခရီး|ကားငှား|"
    # Lao
    r"ໂຮງແຮມ|ການທ່ອງທ່ຽວ|"
    r"ບໍລິສັດທ່ອງທ່ຽວ|ສາຍການບິນ|"
    r"ສະຖານທີ່ພັກຜ່ອນ|ເຮືອທ່ອງທ່ຽວ|"
    # Nepali
    r"होटल|पर्यटन|ट्र्याभल एजेन्सी|"
    r"मोटल|होस्टेल|रिसोर्ट|टुर अपरेटर|"
    r"विमान सेवा|क्रुज|कार भाडा|"
    # Sinhala
    r"හෝටලය|සංචාරක|ගුවන් සේවය|"
    r"සංචාරක නියෝජිත|නිවාඩු නිකේතනය|"
    r"කෲස් සංචාර|කාර් කුලී|"
    # Amharic
    r"ሆቴል|ቱሪዝም|"
    r"የጉዞ ኤጀንሲ|የአየር መንገድ ኩባንያ|መዝናኛ ቦታ|"
    # Yoruba
    r"hótẹ́ẹ̀lì|ìrìnàjò|"
    r"ilé eré ìdárayá|ilé iṣẹ́ ìrìnàjò|ọkọ òfuurufú|"
    # Hausa
    r"otal|yawon shakatawa|kamfanin jiragen sama|"
    r"masaukin baƙi|kamfanin yawon shakatawa|"
    r"haya mota|"
    # Igbo
    r"hotelụ|njegharị|"
    r"ụlọ ezumike|ụlọ ọrụ njem|ụgbọ elu|"
    # Zulu
    r"ihhotela|ezokuvakasha|"
    r"i-resort|i-ejensi yokuvakasha|inkampani yendiza|"
    r"uhambo lokuvakasha|ukuqasha imoto|"
    # Pashto
    r"هوټل|سیاحت|د هوايي چلند شرکت|"
    r"موټل|هوسټل|د سیاحت اداره|"
    r"بحري سفر|د موټر کرایه|"
    # Kurdish
    r"otêl|geştyarî|şirketa hewayî|"
    r"motêl|hostêl|navenda geştyariyê|"
    r"keştiya geştyariyê|kirêya erebeyê|"
    # Tajik
    r"меҳмонхона|сайёҳӣ|ширкати ҳавопаймоӣ|"
    r"мотель|хостел|истироҳатгоҳ|"
    r"круиз|иҷораи мошин|"
    # Kyrgyz
    r"мейманкана|туризм|"
    r"туристтик агенттик|авиакомпания|"
    r"круиз|автоунаа ижарасы|"
    # Maltese
    r"lukanda|turiżmu|aġenzija tal-ivvjaġġar|kumpanija tal-ajru|"
    r"mutel|ostell|resort|tour operatur|"
    r"kruċiera|kiri tal-karozzi|"
    # Luxembourgish
    r"hotel|tourismus|reesbüro|fluchgesellschaft|"
    r"motel|hostel|feriendaarf|tour operateur|"
    r"croisière|autosvermietung|"
    # Haitian Creole
    r"otèl|ajans vwayaj|konpayi avyon|"
    r"motèl|hostèl|sant vakans|operatè touris|"
    r"kwazyè|lokasyon machin|"
    # Frisian
    r"hotel|reisburo|loftfeartmaatskippij|"
    r"motel|fakânsjepark|"
    # Yiddish
    r"האָטעל|רייזע ביוראָ|"
    r"מאָטעל|וואַקאַציע אָרט|"
    # Faroese
    r"gistingarhús|ferðaskrivstova|"
    r"flogfelag|orlovsbýli|"
    # Tatar
    r"кунакханә|сәяхәт агентлыгы|авиакомпания|"
    # Javanese
    r"hotel|biro perjalanan|"
    r"penginapan|wisata|maskapai|"
    # Sundanese
    r"hotel|wisata|"
    # Cebuano
    r"hotel|ahensya sa pagbiyahe|"
    r"motel|resort|kompaniya sa eroplano|"
    r"krus|abang sa awto"
    r")\b"
)

# Food — restaurants, food production, beverage. Common ASN owners are
# restaurant chains and food-service companies.
FOOD_RE = re.compile(
    r"(?i)\b("
    # English
    r"restaurant|food service|food production|food (?:and|&) beverage|"
    r"caterer|catering services|"
    r"brewery|winery|distillery|"
    r"bakery|meat processing|dairy products|food industry|"
    r"restaurant chain|coffee chain|coffee shop chain|"
    # Spanish
    r"restaurante|panadería|alimentación|alimentos|"
    r"servicio de comidas|servicios de catering|"
    r"empresa cervecera|bodega|destilería|"
    r"productos lácteos|industria alimentaria|cafetería|"
    r"cadena de restaurantes|"
    # Portuguese
    r"padaria|alimentação|alimentar|"
    r"restaurante|serviço de alimentação|serviço de catering|"
    r"cervejaria|vinícola|destilaria|"
    r"laticínios|indústria alimentícia|cafeteria|"
    r"rede de restaurantes|"
    # French
    r"patisserie|boulangerie|alimentaire|"
    r"restaurant|service de restauration|service traiteur|"
    r"brasserie|distillerie|domaine viticole|"
    r"produits laitiers|industrie alimentaire|"
    r"chaîne de restaurants|"
    # Italian
    r"ristorante|panetteria|"
    r"servizio di catering|servizio di ristorazione|"
    r"birrificio|cantina vinicola|distilleria|"
    r"prodotti lattiero-caseari|industria alimentare|"
    r"catena di ristoranti|"
    # German
    r"lebensmittel|nahrungsmittel|getränkehersteller|"
    r"restaurantkette|gastronomie|cateringservice|"
    r"brauerei|weingut|brennerei|"
    r"bäckerei|fleischverarbeitung|molkereiprodukte|"
    r"lebensmittelindustrie|"
    # Dutch
    r"restaurantketen|cateringbedrijf|"
    r"brouwerij|wijnmakerij|distilleerderij|"
    r"bakkerij|zuivelproducten|voedingsindustrie|"
    # Polish
    r"przemysł spożywczy|"
    r"restauracja|usługi cateringowe|"
    r"browar|winnica|gorzelnia|"
    r"piekarnia|przetwórstwo mięsne|produkty mleczne|"
    r"sieć restauracji|"
    # Czech
    r"restaurace|cateringové služby|"
    r"pivovar|vinařství|lihovar|"
    r"pekárna|mlékárenské výrobky|potravinářský průmysl|"
    # Slovak
    r"reštaurácia|cateringové služby|"
    r"pivovar|vinárstvo|liehovar|"
    r"pekáreň|potravinársky priemysel|"
    # Russian
    r"производство продуктов питания|пищевая промышленность|"
    r"ресторан|сеть ресторанов|кейтеринг|"
    r"пивоварня|винодельня|ликеро[- ]водочный завод|"
    r"пекарня|мясокомбинат|молочная продукция|"
    # Ukrainian
    r"харчова промисловість|ресторан|кейтеринг|"
    r"пивоварня|виноробня|"
    # Bulgarian
    r"хранителна индустрия|ресторант|"
    r"пивоварна|винарна|"
    # Romanian
    r"restaurant|servicii de catering|"
    r"berărie|cramă|distilerie|"
    r"brutărie|industria alimentară|"
    # Hungarian
    r"étterem|étkezde|catering szolgáltatás|"
    r"sörfőzde|borászat|pálinkafőzde|"
    r"pékség|élelmiszeripar|"
    # Croatian / Serbian / Bosnian
    r"restoran|catering usluge|"
    r"pivovara|vinarija|destilerija|"
    r"pekara|prehrambena industrija|"
    # Slovenian
    r"restavracija|catering storitve|"
    r"pivovarna|vinarstvo|destilarna|"
    r"živilska industrija|"
    # Turkish
    r"restoran|restoran zinciri|"
    r"yemek hizmeti|catering hizmeti|"
    r"bira fabrikası|şarap üreticisi|içki üreticisi|"
    r"fırın|et işleme|süt ürünleri|gıda sanayi|"
    # Albanian
    r"restorant|industria ushqimore|"
    # Greek
    r"εστιατόριο|αλυσίδα εστιατορίων|"
    r"υπηρεσίες catering|"
    r"ζυθοποιία|οινοποιείο|αποστακτήριο|"
    r"αρτοποιείο|γαλακτοκομικά|βιομηχανία τροφίμων|"
    # Estonian
    r"restoran|toitlustusettevõte|"
    r"õlletehas|veinitehas|"
    r"pagariäri|toiduainetööstus|"
    # Latvian
    r"restorāns|ēdināšanas uzņēmums|"
    r"alus darītava|vīna darītava|"
    r"maizes ceptuve|pārtikas rūpniecība|"
    # Lithuanian
    r"restoranas|maitinimo paslaugos|"
    r"alaus darykla|vyno gamykla|"
    r"kepykla|maisto pramonė|"
    # Finnish
    r"ravintola|ravintolaketju|pitopalvelu|"
    r"panimo|viinitila|tislaamo|"
    r"leipomo|elintarviketeollisuus|"
    # Swedish
    r"restaurang|restaurangkedja|catering[- ]?företag|"
    r"bryggeri|vingård|destilleri|"
    r"bageri|livsmedelsindustri|"
    # Norwegian
    r"restaurant|restaurantkjede|cateringfirma|"
    r"bryggeri|vingård|destilleri|"
    r"bakeri|matvareindustri|"
    # Danish
    r"restaurant|restaurantkæde|cateringfirma|"
    r"bryggeri|vingård|destilleri|"
    r"bageri|fødevareindustri|"
    # Persian
    r"رستوران|زنجیره رستوران|خدمات کترینگ|"
    r"کارخانه آبجوسازی|شراب سازی|"
    r"نانوایی|صنعت غذایی|"
    # Arabic
    r"المطعم|إنتاج الأغذية|صناعة الغذاء|"
    r"سلسلة مطاعم|خدمات تموين|"
    r"مصنع جعة|مصنع نبيذ|"
    r"مخبز|منتجات الألبان|"
    # Hebrew
    r"מסעדה|רשת מסעדות|שירותי קייטרינג|"
    r"מבשלת בירה|יקב|מזקקה|"
    r"מאפייה|תעשיית מזון|"
    # Hindi
    r"रेस्तरां|खाद्य उद्योग|डेयरी उत्पाद|"
    # Bengali
    r"রেস্তোরাঁ|খাদ্য শিল্প|"
    # Chinese (Simplified and Traditional)
    r"食品|食物|餐厅|餐廳|"
    r"餐饮服务|餐飲服務|连锁餐厅|連鎖餐廳|"
    r"啤酒厂|啤酒廠|酿酒厂|釀酒廠|蒸馏酒|蒸餾酒|"
    r"面包店|麵包店|乳制品|乳製品|食品工业|食品工業|"
    # Korean
    r"식품|음식|"
    r"레스토랑 체인|급식 서비스|케이터링|"
    r"양조장|와이너리|증류소|"
    r"제과점|유제품|식품 산업|"
    # Japanese
    r"レストラン|食品メーカー|"
    r"レストランチェーン|ケータリングサービス|"
    r"醸造所|ワイナリー|蒸留所|"
    r"ベーカリー|乳製品|食品産業|"
    # Vietnamese
    r"nhà hàng|chuỗi nhà hàng|dịch vụ ăn uống|"
    r"nhà máy bia|nhà máy rượu vang|"
    r"tiệm bánh|sản phẩm sữa|công nghiệp thực phẩm|"
    # Thai
    r"ร้านอาหาร|เชนร้านอาหาร|บริการจัดเลี้ยง|"
    r"โรงเบียร์|โรงไวน์|"
    r"ร้านเบเกอรี่|อุตสาหกรรมอาหาร|"
    # Indonesian
    r"restoran|jaringan restoran|jasa katering|"
    r"pabrik bir|kilang anggur|"
    r"toko roti|industri makanan|"
    # Malay
    r"restoran|rangkaian restoran|perkhidmatan katering|"
    # Filipino (Tagalog)
    r"restawran|kainan|"
    # Catalan
    r"restaurant|forn de pa|fleca|"
    r"indústria alimentària|"
    # Macedonian
    r"ресторан|пекара|винарија|пиварница|"
    r"кафетерија|кетеринг услуги|"
    r"месопреработувачка индустрија|млечни производи|"
    r"прехранбена индустрија|синџир ресторани|"
    # Belarusian
    r"рэстаран|пякарня|"
    r"кавярня|кейтэрынг|вінакурня|бровар|"
    r"малочныя прадукты|харчовая прамысловасць|"
    # Azerbaijani
    r"restoran|çörəkxana|şərab zavodu|qida sənayesi|"
    r"piva zavodu|kafe|keyterinq xidmətləri|"
    r"süd məhsulları|ət emalı|restoran şəbəkəsi|"
    # Georgian
    r"რესტორანი|საცხობი|ღვინის ქარხანა|"
    r"ლუდის ქარხანა|კაფე|კეიტერინგის მომსახურება|"
    r"რძის პროდუქტები|საკვების მრეწველობა|"
    # Armenian
    r"ռեստորան|հացատուն|գարեջրի գործարան|"
    r"գինու գործարան|սրճարան|քեյթերինգի ծառայություններ|"
    r"կաթնամթերք|սննդի արդյունաբերություն|"
    # Kazakh
    r"мейрамхана|нан зауыты|"
    r"кафе|сыра зауыты|шарап зауыты|"
    r"кейтеринг қызметтері|сүт өнімдері|тамақ өнеркәсібі|"
    # Uzbek
    r"restoran|nonvoyxona|"
    r"kafe|pivo zavodi|sharob zavodi|"
    r"keyterink xizmatlari|sut mahsulotlari|oziq-ovqat sanoati|"
    # Mongolian
    r"ресторан|талхны үйлдвэр|"
    r"кафе|пивоны үйлдвэр|дарсны үйлдвэр|"
    r"кейтерингийн үйлчилгээ|сүүн бүтээгдэхүүн|"
    r"хүнсний үйлдвэр|"
    # Khmer
    r"ភោជនីយដ្ឋាន|ហាងនំ|"
    r"ហាងកាហ្វេ|រោងស្រាបៀរ|រោងស្រា|"
    r"សេវាកម្មរៀបចំចំណីអាហារ|ផលិតផលទឹកដោះ|"
    r"ឧស្សាហកម្មចំណីអាហារ|"
    # Burmese
    r"စားသောက်ဆိုင်|မုန့်ဆိုင်|"
    r"ကော်ဖီဆိုင်|ဘီယာစက်ရုံ|ဝိုင်စက်ရုံ|"
    r"ပွဲစီစဉ်ထောက်ပံ့မှု|နို့ထွက်ပစ္စည်းများ|"
    r"အစားအသောက်ထုတ်လုပ်ရေး|"
    # Lao
    r"ຮ້ານອາຫານ|ຮ້ານເບເກີຣີ|"
    r"ຮ້ານກາເຟ|ໂຮງຕົ້ມເບຍ|ໂຮງງານໄວນ໌|"
    r"ບໍລິການລ້ຽງລ້ຽງ|ຜະລິດຕະພັນນົມ|ອຸດສາຫະກໍາອາຫານ|"
    # Nepali
    r"रेस्टुरेन्ट|बेकरी|"
    r"क्याफे|बियर कारखाना|वाइनरी|"
    r"क्याटरिङ सेवा|दुग्ध उत्पादन|खाद्य उद्योग|"
    # Sinhala
    r"ආපනශාලාව|බේකරිය|"
    r"කෝපි කඩය|බියර් කර්මාන්තය|"
    r"කේටරින් සේවා|කිරි නිෂ්පාදන|ආහාර කර්මාන්තය|"
    # Amharic
    r"ሬስቶራንት|ቤከሪ|ካፌ|"
    r"ቢራ ፋብሪካ|ጠጅ ቤት|"
    r"የምግብ አቅርቦት አገልግሎት|የወተት ተዋጽኦ|የምግብ ኢንዱስትሪ|"
    # Yoruba
    r"ilé oúnjẹ|ilé búrẹ́dì|kafe|"
    r"ilé iṣẹ́ ọtí|"
    r"iṣẹ́ ìpèsè oúnjẹ|àwọn ọjà miliki|iṣẹ́ oúnjẹ|"
    # Hausa
    r"gidan abinci|gidan burodi|gidan kofi|"
    r"masana'antar giya|"
    r"sabis na abinci|kayan kiwo|masana'antar abinci|"
    # Igbo
    r"ụlọ nri|ụlọ achịcha|ebe na-ere kọfị|"
    r"ụlọ ọrụ ihe ọṅụṅụ|ngwaahịa mmiri ara ehi|"
    r"ụlọ ọrụ nri|"
    # Zulu
    r"indawo yokudlela|izindawo zezinkwa|"
    r"i-cafe|inkampani yotshwala|"
    r"izinsiza zokudla|imikhiqizo yobisi|imboni yokudla|"
    # Pashto
    r"رستورانت|د ډوډۍ پخلنځی|"
    r"کافي|د بیر کارخانه|"
    r"د خواړو خدمات|د شیدو محصولات|د خوراکي توکو صنعت|"
    # Kurdish
    r"xwaringeh|nanpêjxane|qehwexane|"
    r"firotgeha bîrayê|firotgeha şerabê|"
    r"xizmetên xwarinê|berhemên şîrî|pîşesaziya xwarinê|"
    # Tajik
    r"ресторан|нонвойхона|"
    r"қаҳвахона|корхонаи пиво|"
    r"хизматрасонии хӯрокворӣ|маҳсулоти ширӣ|саноати хӯрокворӣ|"
    # Kyrgyz
    r"ресторан|нан жайы|"
    r"кафе|пиво заводу|"
    r"кейтеринг кызматы|сүт азыктары|тамак-аш өнөр жайы|"
    # Maltese
    r"ristorant|furnerija|industrija tal-ikel|"
    r"kafetterija|birrerija|distillerija|"
    r"servizzi tal-catering|prodotti tal-ħalib|"
    r"katina ta' ristoranti|"
    # Luxembourgish
    r"restaurant|bäckerei|liewensmëttelindustrie|"
    r"café|brauerei|wäibau|"
    r"cateringservice|mëllechprodukter|restaurantkette|"
    # Haitian Creole
    r"restoran|boulanjri|"
    r"kafe|brasri|"
    r"sèvis manje|pwodwi lèt|endistri manje|chèn restoran|"
    # Frisian
    r"restaurant|bakkerij|"
    r"kafee|brouwerij|"
    r"cateringservice|suvelprodukten|fiedingsyndustry|"
    # Yiddish
    r"רעסטאָראַן|בעקעריי|"
    r"קאַפע|בראַווערייַ|"
    r"קייטערינג סערוויס|מילך פּראָדוקטן|"
    # Faroese
    r"matstova|bakari|"
    r"kaffistova|bryggjarí|matvøruídnaður|"
    # Tatar
    r"ресторан|икмәк пешерүчеләр|"
    r"кафе|сыра заводы|азык-төлек сәнәгате|"
    # Javanese
    r"restoran|warung makan|"
    r"toko roti|kafe|industri makanan|"
    # Sundanese
    r"warung makan|toko roti|"
    # Cebuano
    r"restawran|panaderya|"
    r"kapehan|industriya sa pagkaon|"
    r"serbisyo sa pagkaon"
    r")\b"
)

# Legal — law firms, legal services
LEGAL_RE = re.compile(
    r"(?i)\b("
    # English
    r"law firm|law offices?|attorneys at law|attorney at law|"
    r"legal services|legal counsel|legal advisors|"
    r"corporate law|tax law|family law|"
    r"barristers|solicitors|"
    # Spanish
    r"abogados|despacho de abogados|bufete de abogados|"
    r"servicios jurídicos|asesoría jurídica|"
    r"asesoría legal|consultoría jurídica|"
    # Portuguese
    r"escritório de advocacia|advogados|"
    r"serviços jurídicos|assessoria jurídica|"
    r"consultoria jurídica|"
    # French
    r"avocats|cabinet d'avocats|cabinet juridique|"
    r"services juridiques|conseil juridique|"
    r"conseillers juridiques|notariat|"
    # Italian
    r"avvocati|studio legale|"
    r"servizi legali|consulenza legale|"
    r"consulenti legali|"
    # German
    r"rechtsanwälte|anwaltskanzlei|kanzlei|"
    r"rechtsdienstleistungen|rechtsberatung|"
    r"juristische beratung|"
    # Dutch
    r"advocatenkantoor|advocaten|"
    r"juridisch advies|juridische dienstverlening|"
    # Polish
    r"kancelaria prawna|adwokaci|"
    r"radcy prawni|usługi prawne|"
    r"doradztwo prawne|"
    # Czech
    r"advokátní kancelář|právník|"
    r"právní služby|právní poradenství|"
    # Slovak
    r"advokátska kancelária|advokáti|"
    r"právne služby|právne poradenstvo|"
    # Russian
    r"юридическая фирма|адвокатское бюро|адвокаты|"
    r"юридические услуги|юридическая консультация|"
    r"правовое консультирование|юристы|"
    # Ukrainian
    r"юридична фірма|адвокатське бюро|"
    r"юридичні послуги|адвокати|"
    # Bulgarian
    r"адвокатска кантора|правни услуги|"
    r"юридически услуги|"
    # Romanian
    r"cabinet de avocatură|casa de avocatură|"
    r"servicii juridice|consultanță juridică|"
    # Hungarian
    r"ügyvédi iroda|jogi szolgáltatások|"
    r"jogi tanácsadás|"
    # Greek
    r"δικηγορικό γραφείο|νομικές υπηρεσίες|"
    r"νομικός σύμβουλος|"
    # Turkish
    r"hukuk bürosu|avukatlık|"
    r"hukuk firması|hukuk hizmetleri|"
    r"hukuk danışmanlığı|"
    # Albanian
    r"zyrë avokatie|shërbime ligjore|"
    # Croatian / Serbian / Bosnian
    r"advokatska kancelarija|odvjetnički ured|"
    r"pravne usluge|odvjetnik|"
    # Slovenian
    r"odvetniška pisarna|pravne storitve|"
    r"pravno svetovanje|"
    # Estonian
    r"advokaadibüroo|õigusteenused|"
    r"õigusabi|"
    # Latvian
    r"advokātu birojs|juridiskie pakalpojumi|"
    # Lithuanian
    r"advokatų kontora|teisinės paslaugos|"
    # Finnish
    r"asianajotoimisto|lakiasiaintoimisto|"
    r"oikeudelliset palvelut|lakipalvelut|"
    # Swedish
    r"advokatbyrå|juristbyrå|"
    r"juridiska tjänster|juridisk rådgivning|"
    # Norwegian
    r"advokatfirma|advokatkontor|"
    r"juridiske tjenester|juridisk rådgivning|"
    # Danish
    r"advokatfirma|advokatkontor|"
    r"juridiske ydelser|juridisk rådgivning|"
    # Icelandic
    r"lögmannsstofa|lögfræðiþjónusta|"
    # Persian
    r"شرکت حقوقی|دفتر وکالت|"
    r"خدمات حقوقی|مشاوره حقوقی|"
    # Urdu
    r"وکالت|قانونی خدمات|"
    # Arabic
    r"مكتب محاماة|شركة محاماة|"
    r"خدمات قانونية|استشارات قانونية|"
    # Hebrew
    r"משרד עורכי דין|שירותים משפטיים|"
    r"ייעוץ משפטי|"
    # Hindi
    r"विधि फर्म|कानूनी सेवाएं|"
    r"वकील का कार्यालय|कानूनी सलाहकार|"
    # Bengali
    r"আইনি সংস্থা|আইনি সেবা|"
    r"আইনি পরামর্শ|"
    # Tamil
    r"வழக்கறிஞர் அலுவலகம்|சட்ட சேவைகள்|"
    # Telugu
    r"న్యాయ సేవలు|"
    # Marathi
    r"वकील कार्यालय|कायदेशीर सेवा|"
    # Chinese (Simplified and Traditional)
    r"律师事务所|律師事務所|法律事务所|"
    r"法律服务|法律服務|"
    r"法律顾问|法律顧問|"
    # Japanese
    r"法律事務所|弁護士事務所|"
    r"法律サービス|法律相談|"
    # Korean
    r"법률사무소|로펌|"
    r"법률 서비스|법률 자문|"
    # Vietnamese
    r"công ty luật|văn phòng luật sư|"
    r"dịch vụ pháp lý|tư vấn pháp luật|"
    # Thai
    r"สำนักงานกฎหมาย|บริการทางกฎหมาย|"
    r"ที่ปรึกษากฎหมาย|"
    # Indonesian
    r"firma hukum|kantor hukum|"
    r"layanan hukum|konsultan hukum|"
    # Malay
    r"firma guaman|peguam|"
    r"khidmat undang-undang|"
    # Filipino (Tagalog)
    r"opisina ng abogado|"
    # Swahili
    r"kampuni ya sheria|huduma za kisheria|"
    # Catalan
    r"despatx d'advocats|serveis jurídics|"
    # Galician
    r"despacho de avogados|"
    # Welsh
    r"cwmni cyfreithiol|gwasanaethau cyfreithiol|"
    # Irish
    r"gnólacht dlí|"
    # Afrikaans
    r"prokureursfirma|regsdienste|"
    # Macedonian
    r"адвокатска канцеларија|адвокати|"
    r"правни услуги|правно советување|"
    # Belarusian
    r"адвакацкае бюро|адвакаты|"
    r"юрыдычныя паслугі|юрыдычная кансультацыя|"
    # Azerbaijani
    r"hüquq bürosu|vəkillik|"
    r"hüquqi xidmətlər|hüquqi məsləhət|"
    # Georgian
    r"იურიდიული ფირმა|ადვოკატთა ბიურო|"
    r"იურიდიული მომსახურება|იურიდიული კონსულტაცია|"
    # Armenian
    r"իրավաբանական ընկերություն|փաստաբանական գրասենյակ|"
    r"իրավաբանական ծառայություններ|իրավախորհրդատվություն|"
    # Kazakh
    r"заң фирмасы|адвокаттық кеңсе|"
    r"заң қызметтері|заң кеңесі|"
    # Uzbek
    r"yuridik firma|advokatlar idorasi|"
    r"yuridik xizmatlar|yuridik maslahat|"
    # Mongolian
    r"хуулийн фирм|өмгөөлөгчийн товчоо|"
    r"хуулийн үйлчилгээ|хуулийн зөвлөгөө|"
    # Khmer
    r"ការិយាល័យមេធាវី|ក្រុមហ៊ុនច្បាប់|"
    r"សេវាកម្មច្បាប់|ប្រឹក្សាច្បាប់|"
    # Burmese
    r"ဥပဒေ ကုမ္ပဏီ|ရှေ့နေရုံး|"
    r"ဥပဒေဆိုင်ရာ ဝန်ဆောင်မှု|ဥပဒေအကြံပေး|"
    # Lao
    r"ບໍລິສັດທະນາຍຄວາມ|ຫ້ອງການທະນາຍຄວາມ|"
    r"ບໍລິການທາງດ້ານກົດໝາຍ|"
    # Nepali
    r"कानुनी फर्म|अधिवक्ता कार्यालय|"
    r"कानुनी सेवा|कानुनी परामर्श|"
    # Sinhala
    r"නීතී ආයතනය|නීතිඥ කාර්යාලය|"
    r"නීතිමය සේවා|නීතිමය උපදේශන|"
    # Amharic
    r"የሕግ ድርጅት|የጠበቃ ቢሮ|"
    r"የሕግ አገልግሎት|የሕግ ምክር|"
    # Yoruba
    r"ilé iṣẹ́ amòfin|ọ́fíìsì agbẹjọ́rò|"
    r"iṣẹ́ ìbágbín òfin|"
    # Hausa
    r"kamfanin shari'a|ofishin lauya|"
    r"sabis na shari'a|shawarwarin shari'a|"
    # Igbo
    r"ụlọ ọrụ iwu|ọfịs ọkàiwu|"
    r"ọrụ iwu|ndụmọdụ iwu|"
    # Zulu
    r"i-firm yezomthetho|i-ofisi yommeli|"
    r"izinsiza zezomthetho|izeluleko zezomthetho|"
    # Pashto
    r"حقوقي شرکت|د محامیانو دفتر|"
    r"حقوقي خدمات|حقوقي مشاوره|"
    # Kurdish
    r"şirketa hiqûqî|ofîsa parêzeran|"
    r"xizmetên hiqûqî|şêwirdariya hiqûqî|"
    # Tajik
    r"ширкати ҳуқуқӣ|идораи адвокатҳо|"
    r"хизматрасонии ҳуқуқӣ|маслиҳати ҳуқуқӣ|"
    # Kyrgyz
    r"юридикалык фирма|адвокаттык контора|"
    r"юридикалык кызматтар|юридикалык кеңеш|"
    # Maltese
    r"ditta legali|uffiċċju tal-avukati|"
    r"servizzi legali|konsulenza legali|"
    # Luxembourgish
    r"affekot|affekotenkanzlei|"
    r"juristesch déngschtleeschtungen|juristesch beroodung|"
    # Haitian Creole
    r"kabinè avoka|biwo avoka|"
    r"sèvis legal|konsiltasyon legal|"
    # Frisian
    r"advokatekantoar|"
    r"juridyske tsjinsten|juridysk advys|"
    # Yiddish
    r"געזעצליכע פירמע|"
    # Faroese
    r"løgmannsstova|"
    # Tatar
    r"юридик фирма|адвокат бүлмәсе|"
    # Javanese
    r"firma hukum|kantor advokat|"
    r"layanan hukum|"
    # Sundanese
    r"firma hukum|"
    # Cebuano
    r"law firm|opisina sa abogado|"
    r"serbisyo nga ligal|konsultasyon ligal"
    r")\b"
)

# Real estate
REAL_ESTATE_RE = re.compile(
    r"(?i)\b("
    # English
    r"real estate|realtor|realty|"
    r"property listings|properties for sale|"
    r"residential properties|commercial properties|"
    r"property management|facility management|property facility|"
    r"property development|property developer|"
    r"shopping mall management|business center management|business centre management|"
    r"coworking|co-working|"
    r"estate agent|estate agency|"
    # Spanish
    r"inmobiliaria|bienes raíces|gestión inmobiliaria|"
    r"agencia inmobiliaria|propiedades en venta|"
    r"desarrollo inmobiliario|promotor inmobiliario|"
    r"administración de propiedades|coworking|"
    # Portuguese
    r"imobiliária|imóveis|gestão imobiliária|"
    r"imóveis à venda|incorporadora imobiliária|"
    r"administração de imóveis|coworking|"
    # French
    r"immobilier|agence immobilière|gestion immobilière|"
    r"biens immobiliers|propriétés à vendre|"
    r"promoteur immobilier|développeur immobilier|"
    r"gestion de patrimoine immobilier|coworking|"
    # Italian
    r"agenzia immobiliare|gestione immobiliare|immobiliare|"
    r"immobili in vendita|sviluppo immobiliare|"
    r"costruttore immobiliare|amministrazione immobili|"
    r"spazio coworking|"
    # German
    r"immobilien|maklerbüro|immobilienverwaltung|"
    r"immobilienmakler|immobilienagentur|"
    r"hausverwaltung|projektentwickler|"
    r"bauträger|coworking[- ]?space|"
    # Dutch
    r"makelaardij|vastgoed|"
    r"makelaarskantoor|vastgoedbeheer|"
    r"vastgoedontwikkelaar|coworking|"
    # Polish
    r"nieruchomości|biuro nieruchomości|zarządzanie nieruchomościami|"
    r"agencja nieruchomości|deweloper|"
    r"obrót nieruchomościami|coworking|"
    # Czech
    r"realitní kancelář|nemovitosti|"
    r"realitní agentura|developer nemovitostí|"
    r"správa nemovitostí|coworking|"
    # Slovak
    r"realitná kancelária|nehnuteľnosti|"
    r"developer nehnuteľností|správa nehnuteľností|"
    # Russian
    r"недвижимость|агентство недвижимости|"
    r"управление и эксплуатация (?:бизнес-центров|торговых центров)|"
    r"риелтор|риэлтор|агент по недвижимости|"
    r"управление недвижимостью|девелопер|застройщик|"
    r"коворкинг|"
    # Ukrainian
    r"нерухомість|агентство нерухомості|"
    r"забудовник|управління нерухомістю|"
    # Bulgarian
    r"имоти|агенция за недвижими имоти|"
    r"посредник за недвижими имоти|"
    # Romanian
    r"agenție imobiliară|imobiliare|"
    r"dezvoltator imobiliar|management imobiliar|"
    r"coworking|"
    # Hungarian
    r"ingatlaniroda|ingatlanügynökség|"
    r"ingatlanforgalmazó|ingatlanfejlesztő|"
    r"ingatlankezelés|"
    # Greek
    r"κτηματομεσιτικό γραφείο|ακίνητα|"
    r"μεσιτικό γραφείο|διαχείριση ακινήτων|"
    r"κατασκευαστής ακινήτων|"
    # Turkish
    r"emlak ofisi|gayrimenkul|emlak danışmanı|"
    r"emlak yönetimi|gayrimenkul geliştiricisi|"
    # Albanian
    r"agjenci patundshmërish|"
    # Croatian / Serbian / Bosnian
    r"agencija za nekretnine|nekretnine|"
    r"upravljanje nekretninama|"
    # Slovenian
    r"nepremičninska agencija|nepremičnine|"
    r"upravljanje nepremičnin|"
    # Estonian
    r"kinnisvarabüroo|kinnisvara|"
    r"kinnisvaraarendaja|"
    # Latvian
    r"nekustamā īpašuma birojs|nekustamais īpašums|"
    # Lithuanian
    r"nekilnojamojo turto agentūra|"
    r"nekilnojamasis turtas|"
    # Finnish
    r"kiinteistönvälitys|kiinteistövälittäjä|"
    r"kiinteistönhoito|"
    # Swedish
    r"fastighetsmäklare|fastighetsbyrå|"
    r"fastighetsförvaltning|"
    # Norwegian
    r"eiendomsmegler|eiendomsforvaltning|"
    # Danish
    r"ejendomsmægler|ejendomsadministration|"
    # Icelandic
    r"fasteignasala|fasteignaumsýsla|"
    # Persian
    r"املاک|دفتر مشاور املاک|مدیریت املاک|"
    # Urdu
    r"رئیل اسٹیٹ|"
    # Arabic
    r"عقارات|وكالة عقارية|"
    r"تطوير عقاري|إدارة العقارات|"
    # Hebrew
    r"נדל\"ן|תיווך נדל\"ן|ניהול נכסים|"
    # Hindi
    r"रियल एस्टेट|संपत्ति|"
    r"प्रॉपर्टी प्रबंधन|"
    # Bengali
    r"রিয়েল এস্টেট|আবাসন|"
    # Tamil
    r"ரியல் எஸ்டேட்|"
    # Chinese (Simplified and Traditional)
    r"房地产|不动产|房地產|不動產|物业管理|物業管理|"
    r"地产中介|地產中介|地产开发|地產開發|"
    r"房地产经纪|房地產經紀|"
    # Japanese
    r"不動産|不動産仲介|"
    r"不動産管理|不動産開発|"
    # Korean
    r"부동산|부동산 중개|"
    r"부동산 관리|부동산 개발|"
    # Vietnamese
    r"bất động sản|môi giới bất động sản|"
    r"quản lý bất động sản|phát triển bất động sản|"
    # Thai
    r"อสังหาริมทรัพย์|นายหน้าอสังหาริมทรัพย์|"
    r"การบริหารอสังหาริมทรัพย์|"
    # Indonesian
    r"properti|real estat|"
    r"agensi properti|pengelolaan properti|"
    # Malay
    r"hartanah|agensi hartanah|"
    # Filipino (Tagalog)
    r"real estate|ahensya ng real estate|"
    # Catalan
    r"immobiliària|gestió immobiliària|"
    # Galician
    r"inmobiliaria|"
    # Afrikaans
    r"eiendomsagent|eiendomsagentskap|"
    # Macedonian
    r"недвижности|агенција за недвижности|"
    r"управување со недвижности|развој на недвижности|"
    r"станбени имоти|деловни имоти|коворкинг|"
    # Belarusian
    r"нерухомасць|агенцтва нерухомасці|"
    r"кіраванне нерухомасцю|девелопер|"
    r"жыллёвая нерухомасць|камерцыйная нерухомасць|"
    # Azerbaijani
    r"daşınmaz əmlak|əmlak agentliyi|"
    r"əmlak idarəçiliyi|tikinti şirkəti|"
    r"yaşayış əmlakı|kommersiya əmlakı|"
    # Georgian
    r"უძრავი ქონება|უძრავი ქონების სააგენტო|"
    r"ქონების მართვა|ქონების განვითარება|"
    r"საცხოვრებელი ქონება|კომერციული ქონება|"
    # Armenian
    r"անշարժ գույք|անշարժ գույքի գործակալություն|"
    r"գույքի կառավարում|անշարժ գույքի զարգացում|"
    r"բնակելի անշարժ գույք|առևտրային անշարժ գույք|"
    # Kazakh
    r"жылжымайтын мүлік|жылжымайтын мүлік агенттігі|"
    r"мүлікті басқару|жылжымайтын мүлікті дамыту|"
    r"тұрғын үй|коммерциялық жылжымайтын мүлік|"
    # Uzbek
    r"ko'chmas mulk|ko'chmas mulk agentligi|"
    r"mulkni boshqarish|ko'chmas mulkni rivojlantirish|"
    r"turar joy|tijorat ko'chmas mulki|"
    # Mongolian
    r"үл хөдлөх хөрөнгө|үл хөдлөх хөрөнгийн агентлаг|"
    r"үл хөдлөх хөрөнгийн менежмент|"
    r"орон сууц|арилжааны үл хөдлөх|"
    # Khmer
    r"អចលនទ្រព្យ|ភ្នាក់ងារអចលនទ្រព្យ|"
    r"ការគ្រប់គ្រងអចលនទ្រព្យ|អភិវឌ្ឍន៍អចលនទ្រព្យ|"
    # Burmese
    r"အိမ်ခြံမြေ|အိမ်ခြံမြေအေဂျင်စီ|"
    r"အိမ်ခြံမြေ စီမံခန့်ခွဲမှု|အိမ်ခြံမြေဖွံ့ဖြိုးမှု|"
    # Lao
    r"ອະສັງຫາລິມະຊັບ|ບໍລິສັດອະສັງຫາຣິມະຊັບ|"
    r"ການຄຸ້ມຄອງອະສັງຫາລິມະຊັບ|"
    # Nepali
    r"घर जग्गा|रियल इस्टेट एजेन्सी|"
    r"सम्पत्ति व्यवस्थापन|रियल इस्टेट विकास|"
    # Sinhala
    r"දේපල වෙළඳාම|දේපල නියෝජිතායතනය|"
    r"දේපල කළමනාකරණය|"
    # Amharic
    r"የቤት ሽያጭ|የቤት ኤጀንሲ|"
    r"የንብረት አስተዳደር|"
    # Yoruba
    r"ilé àti ìpín ilẹ̀|ilé iṣẹ́ ríṣàn ilẹ̀|"
    r"ìṣàkóso àbúdá|"
    # Hausa
    r"gidaje da kasashe|kamfanin sayar da gida|"
    r"gudanar da dukiya|gina gidaje|"
    # Igbo
    r"akụ na ụba ala|ụlọ ọrụ akụ ụlọ|"
    r"njikwa akụ ụlọ|"
    # Zulu
    r"izindlu nezindawo|i-ejensi yezindlu|"
    r"ukuphathwa kwempahla|ukuthuthukiswa kwezindawo|"
    # Pashto
    r"غیر منقول ملکیت|د املاکو اداره|"
    r"د جایداد اداره|د املاکو پراختیا|"
    # Kurdish
    r"milkê neguhêz|navenda firotina malan|"
    r"rêveberiya milkan|geşepêdana milkan|"
    # Tajik
    r"молу мулки ғайриманқул|агентии амвол|"
    r"идоракунии амвол|"
    # Kyrgyz
    r"кыймылсыз мүлк|кыймылсыз мүлк агенттиги|"
    r"мүлктү башкаруу|"
    # Maltese
    r"propjetà immobbli|aġenzija tal-propjetà|"
    r"ġestjoni tal-propjetà|żvilupp tal-propjetà|"
    r"propjetà residenzjali|propjetà kummerċjali|"
    # Luxembourgish
    r"immobilien|immobilieagentur|"
    r"immobilieverwaltung|immobilien[- ]entwécklung|"
    r"wunngebai|kommerziell immobilien|"
    # Haitian Creole
    r"byen imobilye|ajans byen imobilye|"
    r"jesyon byen|devlòpman byen|"
    # Frisian
    r"unreplik guod|makelder|"
    r"unreplik[- ]guod[- ]beheer|"
    # Yiddish
    r"רעאַל עסטעיט|"
    # Faroese
    r"fasta ogn|fasta ognasala|"
    # Tatar
    r"күчемсез мөлкәт|күчемсез мөлкәт агентлыгы|"
    # Javanese
    r"properti|agen properti|"
    r"manajemen properti|"
    # Sundanese
    r"properti|agen properti|"
    # Cebuano
    r"real estate|ahensya sa real estate|"
    r"pagdumala sa propyedad"
    r")\b"
)

# Finance — body-text detector that catches insurance, investment firms,
# asset management, brokerage, and similar non-bank financials. The
# narrow `(bank|banca|banco|banque)` as_name fallback elsewhere only
# covers actual banks; this catches the rest.
FINANCE_RE = re.compile(
    r"(?i)\b("
    # Core concepts: bank, insurance, investment fund, asset/wealth
    # management, brokerage, payments, credit union, financial services.
    # Each translated below across all major world languages.
    # English
    r"insurance company|insurance group|mutual insurance|"
    r"property and casualty insurer|p&c insurer|"
    r"life insurance|health insurance|insurance broker|"
    r"underwriter|insurance underwriting|insurer\b|"
    r"asset management|wealth management|investment management|"
    r"investment firm|investment company|investment fund|"
    r"private equity|hedge fund|venture capital firm|"
    r"securities firm|broker[- ]?dealer|stock brokerage|"
    r"capital management|fund management|"
    r"credit union|credit cooperative|building society|"
    r"financial services|financial group|financial planning|"
    r"banking group|retail bank|commercial bank|"
    r"payment processor|payment platform|payments company|"
    # Spanish
    r"asegurad|seguros|aseguradora|compañía de seguros|"
    r"banca|bancario|banco de|caja de ahorros|"
    r"gestora|fondo de inversión|gestión de activos|"
    r"servicios financieros|sociedad de inversión|"
    r"cooperativa de crédito|gestión patrimonial|"
    r"corredor de bolsa|casa de bolsa|"
    # Portuguese
    r"seguradora|fundo de investimento|investimentos|"
    r"serviços financeiros|gestão de ativos|"
    r"corretora|corretora de seguros|cooperativa de crédito|"
    r"banco comercial|banco de varejo|"
    # French
    r"assurance|cabinet d'assurance|courtier en assurance|"
    r"caisse d'épargne|banque populaire|banque privée|"
    r"société de gestion|fonds d'investissement|"
    r"services financiers|gestion de patrimoine|"
    r"compagnie d'assurance|coopérative de crédit|"
    # Italian
    r"assicurazione|assicurazioni|compagnia di assicurazioni|"
    r"banca cooperativa|gestione patrimoniale|servizi finanziari|"
    r"fondo di investimento|società di gestione|"
    r"banca commerciale|cooperativa di credito|"
    # German
    r"versicherung|versicherungsgesellschaft|"
    r"vermögensverwaltung|kapitalverwaltung|"
    r"sparkasse|volksbank|raiffeisenbank|finanzdienstleistung|"
    r"investmentfonds|kreditgenossenschaft|"
    # Dutch
    r"verzekeringsmaatschappij|spaarbank|verzekeraar|"
    r"vermogensbeheer|financiële dienstverlening|"
    # Polish
    r"ubezpieczenia|towarzystwo ubezpieczeń|"
    r"bank spółdzielczy|fundusz inwestycyjny|"
    r"zarządzanie aktywami|usługi finansowe|"
    r"firma ubezpieczeniowa|"
    # Czech
    r"pojišťovna|investiční společnost|finanční služby|"
    r"družstevní záložna|správa aktiv|banka|"
    # Slovak
    r"poisťovňa|investičná spoločnosť|finančné služby|"
    # Russian
    r"страхование|страховая компания|"
    r"инвестиционная компания|управляющая компания|"
    r"банк|сбербанк|банковские услуги|финансовые услуги|"
    r"кредитный союз|управление активами|"
    # Ukrainian
    r"страхова компанія|банк|інвестиційна компанія|"
    # Bulgarian
    r"застрахователна компания|банка|инвестиционен фонд|"
    # Romanian
    r"companie de asigurări|bancă|fond de investiții|"
    r"servicii financiare|"
    # Hungarian
    r"biztosító|bank|befektetési alap|"
    # Greek
    r"ασφαλιστική εταιρεία|τράπεζα|χρηματοοικονομικ|"
    r"επενδυτική εταιρεία|"
    # Albanian
    r"kompani sigurimesh|bankë|fond investimi|"
    # Turkish
    r"sigorta şirketi|sigortacılık|"
    r"yatırım şirketi|yatırım fonu|finansal hizmet|"
    r"banka|kredi kooperatifi|varlık yönetimi|"
    # Slovenian
    r"zavarovalnica|banka|investicijski sklad|"
    # Croatian / Serbian / Bosnian
    r"osiguravajuće društvo|banka|investicijski fond|"
    # Estonian
    r"kindlustusselts|pank|investeerimisfond|"
    # Latvian
    r"apdrošināšanas sabiedrība|banka|ieguldījumu fonds|"
    # Lithuanian
    r"draudimo bendrovė|bankas|investicinis fondas|"
    # Finnish
    r"vakuutusyhtiö|pankki|sijoitusrahasto|"
    # Swedish
    r"försäkringsbolag|bank|investeringsfond|"
    # Norwegian
    r"forsikringsselskap|bank|investeringsfond|"
    # Danish
    r"forsikringsselskab|bank|investeringsfond|"
    # Icelandic
    r"tryggingafélag|banki|fjárfestingarsjóður|"
    # Persian
    r"شرکت بیمه|بانک|صندوق سرمایه گذاری|"
    # Urdu
    r"انشورنس کمپنی|بینک|"
    # Arabic
    r"شركة تأمين|بنك|مصرف|صندوق استثمار|خدمات مالية|"
    # Hebrew
    r"חברת ביטוח|בנק|קרן השקעות|שירותים פיננסיים|"
    # Hindi
    r"बीमा कंपनी|बैंक|निवेश कोष|वित्तीय सेवाएं|"
    # Bengali
    r"বীমা কোম্পানি|ব্যাংক|বিনিয়োগ তহবিল|"
    # Tamil
    r"காப்பீட்டு நிறுவனம்|வங்கி|முதலீட்டு நிதி|"
    # Telugu
    r"బీమా కంపెనీ|బ్యాంక్|"
    # Marathi
    r"विमा कंपनी|बँक|"
    # Punjabi
    r"ਬੀਮਾ ਕੰਪਨੀ|ਬੈਂਕ|"
    # Chinese (Simplified and Traditional)
    r"保险公司|保險公司|银行|銀行|投资公司|投資公司|"
    r"金融服务|金融服務|资产管理|資產管理|信用合作社|"
    # Japanese
    r"保険会社|投資|金融|資産運用|信用組合|"
    # Korean
    r"보험|보험회사|은행|투자회사|금융서비스|자산운용|"
    r"신용협동조합|"
    # Vietnamese
    r"công ty bảo hiểm|ngân hàng|đầu tư|quỹ đầu tư|"
    r"dịch vụ tài chính|"
    # Thai
    r"บริษัทประกันภัย|ธนาคาร|กองทุนการลงทุน|"
    # Indonesian
    r"perusahaan asuransi|bank|reksa dana|jasa keuangan|"
    # Malay
    r"syarikat insurans|bank|dana pelaburan|"
    # Filipino (Tagalog)
    r"kompanya ng seguro|bangko|"
    # Swahili
    r"kampuni ya bima|benki|"
    # Catalan
    r"companyia d'assegurances|banc|fons d'inversió|"
    # Galician
    r"compañía de seguros|banco|"
    # Basque
    r"aseguru-etxe|banku|"
    # Welsh
    r"cwmni yswiriant|banc|"
    # Irish
    r"comhlacht árachais|banc|"
    # Afrikaans
    r"versekeringsmaatskappy|bank|"
    # Macedonian
    r"банка|осигурителна компанија|"
    r"инвестициски фонд|финансиски услуги|"
    r"штедилница|кредитна институција|"
    r"друштво за управување со средства|брокерска куќа|"
    # Belarusian
    r"банк|страхавая кампанія|"
    r"інвестыцыйны фонд|фінансавыя паслугі|"
    r"крэдытны саюз|кампанія па кіраванні актывамі|"
    # Azerbaijani
    r"bank|sığorta şirkəti|investisiya fondu|"
    r"maliyyə xidmətləri|kredit ittifaqı|"
    r"aktivlərin idarə edilməsi|broker firması|"
    # Georgian
    r"ბანკი|სადაზღვევო კომპანია|საინვესტიციო ფონდი|"
    r"ფინანსური მომსახურება|საკრედიტო კავშირი|"
    r"აქტივების მართვა|საბროკერო კომპანია|"
    # Armenian
    r"բանկ|ապահովագրական ընկերություն|"
    r"ներդրումային հիմնադրամ|ֆինանսական ծառայություններ|"
    r"վարկային միություն|ակտիվների կառավարում|բրոքերային|"
    # Kazakh
    r"банк|сақтандыру компаниясы|"
    r"инвестициялық қор|қаржылық қызметтер|"
    r"несие қоғамы|активтерді басқару|брокерлік|"
    # Uzbek
    r"bank|sug'urta kompaniyasi|"
    r"investitsiya fondi|moliyaviy xizmatlar|"
    r"kredit ittifoqi|aktivlarni boshqarish|brokerlik|"
    # Mongolian
    r"банк|даатгалын компани|"
    r"хөрөнгө оруулалтын сан|санхүүгийн үйлчилгээ|"
    r"зээлийн холбоо|хөрөнгийн менежмент|брокерийн|"
    # Khmer
    r"ធនាគារ|ក្រុមហ៊ុនធានារ៉ាប់រង|"
    r"មូលនិធិវិនិយោគ|សេវាហិរញ្ញវត្ថុ|"
    r"សហករណ៍ឥណទាន|"
    # Burmese
    r"ဘဏ်|အာမခံကုမ္ပဏီ|"
    r"ရင်းနှီးမြှုပ်နှံမှုရန်ပုံငွေ|ငွေရေးကြေးရေး ဝန်ဆောင်မှု|"
    r"ချေးငွေ အသင်း|ပိုင်ဆိုင်မှု စီမံခန့်ခွဲမှု|"
    # Lao
    r"ທະນາຄານ|ບໍລິສັດປະກັນໄພ|"
    r"ກອງທຶນລົງທຶນ|ບໍລິການການເງິນ|"
    # Nepali
    r"बैंक|बीमा कम्पनी|"
    r"लगानी कोष|वित्तीय सेवाहरू|"
    r"सहकारी संस्था|सम्पत्ति व्यवस्थापन|दलाली|"
    # Sinhala
    r"බැංකුව|රක්ෂණ සමාගම|"
    r"ආයෝජන අරමුදල|මූල්‍ය සේවා|"
    r"සමුපකාර සංගමය|වත්කම් කළමනාකරණය|"
    # Amharic
    r"ባንክ|የኢንሹራንስ ኩባንያ|"
    r"የኢንቨስትመንት ፈንድ|የፋይናንስ አገልግሎቶች|"
    r"የብድር ማህበር|"
    # Yoruba
    r"báńkì|ilé iṣẹ́ ìpamọ́|"
    r"ètò ìnáwó|àjọ ìrànlọ́wọ́ owó|"
    # Hausa
    r"banki|kamfanin inshora|"
    r"asusun saka hannun jari|sabis na kuɗi|"
    r"kungiyar lamuni|sarrafa kadara|"
    # Igbo
    r"ụlọ akụ|ụlọ ọrụ mkpuchi|"
    r"ego ntinye ego|ọrụ ego|otu mbinye ego|"
    # Zulu
    r"ibhange|inkampani yomshwalense|"
    r"isikhwama sokutshala imali|ezezimali|"
    r"inhlangano yezikweletu|ukuphathwa kwempahla|"
    # Pashto
    r"بانک|د بیمې شرکت|"
    r"د پانگه اچونې فنډ|مالي خدمات|"
    r"د پور اتحادیه|"
    # Kurdish
    r"bank|şirketa sîgorteyê|"
    r"fonda veberhênanê|xizmetên darayî|"
    r"yekîtiya krediyê|rêveberiya sermayê|"
    # Tajik
    r"бонк|ширкати суғурта|"
    r"фонди сармоягузорӣ|хизматрасониҳои молиявӣ|"
    r"иттиҳоди қарзӣ|идоракунии дороиҳо|"
    # Kyrgyz
    r"банк|камсыздандыруу компаниясы|"
    r"инвестициялык фонд|финансылык кызматтар|"
    r"кредиттик союз|активдерди башкаруу|"
    # Maltese
    r"bank|kumpanija ta' assigurazzjoni|"
    r"fond ta' investiment|servizzi finanzjarji|"
    r"unjoni tal-kreditu|maniġment tal-assi|sensariji|"
    # Luxembourgish
    r"bank|versécherungsgesellschaft|"
    r"investmentfong|finanzdéngschtleeschtungen|"
    r"kreditgenossenschaft|verméigensverwaltung|broker|"
    # Haitian Creole
    r"bank|konpayi asirans|"
    r"fon envèstisman|sèvis finansye|"
    r"inyon kredi|jesyon byen|kourtye|"
    # Frisian
    r"bank|fersekeringsmaatskippij|"
    r"ynvestearringsfûns|finansjele tsjinsten|"
    r"krediettferiening|"
    # Yiddish
    r"באַנק|פאַרזיכערונג קאָמפּאַניע|"
    r"אינוועסטיציע פאָנד|פינאַנציעלע סערוויסעס|"
    # Faroese
    r"banki|tryggingarfelag|"
    r"íløgufeløg|fíggjarligar tænastur|"
    # Tatar
    r"банк|иминият компаниясе|"
    r"инвестиция фонды|финанс хезмәтләре|"
    # Javanese
    r"bank|perusahaan asuransi|"
    r"dana investasi|layanan keuangan|"
    # Sundanese
    r"bank|asuransi|"
    # Cebuano
    r"bangko|kompaniya sa insyurans|"
    r"pondo sa pamuhunan|serbisyo sa panalapi|"
    r"unyon sa kredito"
    r")\b"
)

# Automotive — dealers, auto manufacturers, auto parts
AUTOMOTIVE_RE = re.compile(
    r"(?i)\b("
    # English
    r"car dealer|auto dealer|auto dealership|"
    r"dealership for|car dealership|"
    r"car parts|auto parts|automotive parts|automotive supplier|"
    r"car rental|auto rental|car repair shop|"
    r"new and used cars|new & used cars|"
    r"used cars?|preowned vehicles?|"
    r"auto repair|automotive service|"
    r"tire shop|tire store|tire dealer|tire and auto|"
    r"tyre shop|tyre store|tyre dealer|tyre and auto|tyre fitter|"
    # Spanish
    r"concesionario|concesionario de automóviles|"
    r"alquiler de coches|alquiler de autos|"
    r"venta de autos|repuestos automotrices|repuestos para autos|"
    r"piezas para autos|piezas de automóvil|"
    r"taller mecánico|taller automotriz|"
    r"tienda de neumáticos|tienda de llantas|venta de neumáticos|"
    # Portuguese
    r"concessionária|concessionária de veículos|"
    r"aluguel de carros|locadora de veículos|"
    r"peças automotivas|autopeças|peças de carro|"
    r"oficina mecânica|loja de pneus|venda de pneus|"
    r"venda de carros usados|"
    # French
    r"concessionnaire automobile|garage automobile|"
    r"location de voiture|location de véhicules|"
    r"pièces détachées auto|pièces automobiles|"
    r"pièces auto|centre auto|"
    r"vente de pneus|centre de pneus|pneumaticien|"
    r"vente de voitures d'occasion|réparation automobile|"
    # Italian
    r"concessionaria auto|concessionaria d'auto|"
    r"noleggio auto|ricambi auto|ricambi automobilistici|"
    r"officina meccanica|gommista|vendita pneumatici|"
    r"vendita auto usate|"
    # German
    r"autohaus|fahrzeughändler|kfz[- ]?werkstatt|"
    r"autovermietung|autoersatzteile|kfz[- ]?ersatzteile|"
    r"reifenhandel|reifenservice|reifenhändler|"
    r"gebrauchtwagen|neuwagen|autoteile|"
    # Dutch
    r"autoverhuur|autodealer|autobedrijf|"
    r"auto-?onderdelen|garagebedrijf|"
    r"tweedehands auto|bandencentrum|bandenhandel|"
    # Polish
    r"salon samochodowy|dealer samochodowy|"
    r"wypożyczalnia samochodów|części samochodowe|"
    r"warsztat samochodowy|samochody używane|"
    r"sklep z oponami|wymiana opon|"
    # Czech
    r"autosalon|prodejce automobilů|"
    r"půjčovna aut|autodíly|"
    r"autoservis|ojeté vozy|pneuservis|prodej pneumatik|"
    # Slovak
    r"autosalón|predajca automobilov|"
    r"požičovňa áut|autodiely|autoservis|"
    r"jazdené vozidlá|pneuservis|predaj pneumatík|"
    # Russian
    r"автосалон|автодилер|автоцентр|"
    r"прокат автомобилей|аренда автомобилей|"
    r"автозапчасти|запчасти для автомобилей|"
    r"автосервис|шиномонтаж|шинный центр|"
    r"подержанные автомобили|"
    # Ukrainian
    r"автосалон|прокат автомобілів|"
    r"автозапчастини|автосервіс|шиномонтаж|"
    # Bulgarian
    r"автокъща|автосервиз|автомобилни части|"
    r"под наем автомобили|магазин за гуми|"
    # Romanian
    r"dealer auto|service auto|piese auto|"
    r"închirieri auto|mașini second hand|vulcanizare|"
    r"magazin de anvelope|"
    # Hungarian
    r"autókereskedő|autókereskedés|"
    r"autóbérlés|autóalkatrészek|"
    r"autószerviz|használt autó|gumiabroncs|gumiszerviz|"
    # Greek
    r"αντιπροσωπεία αυτοκινήτων|"
    r"ενοικίαση αυτοκινήτων|ανταλλακτικά αυτοκινήτων|"
    r"συνεργείο αυτοκινήτων|μεταχειρισμένα αυτοκίνητα|"
    r"κατάστημα ελαστικών|βουλκανιζατέρ|"
    # Turkish
    r"otomobil bayisi|otomobil bayii|"
    r"araç kiralama|oto yedek parça|"
    r"oto servis|ikinci el araç|lastik bayii|lastik mağazası|"
    # Albanian
    r"shitje automjetesh|servis makinash|pjesë këmbimi|"
    # Croatian / Serbian / Bosnian
    r"prodaja automobila|prodaja vozila|"
    r"rent[- ]a[- ]car|auto dijelovi|"
    r"auto servis|polovni automobili|vulkanizer|"
    # Slovenian
    r"prodaja vozil|najem avtomobilov|"
    r"avtodeli|avtoservis|rabljena vozila|"
    # Estonian
    r"autode müük|autorent|autovaruosad|"
    r"autoremont|kasutatud autod|"
    # Latvian
    r"automašīnu tirdzniecība|automašīnu noma|"
    r"auto rezerves daļas|autoserviss|lietotas automašīnas|"
    # Lithuanian
    r"automobilių salonas|automobilių nuoma|"
    r"automobilių dalys|autoservisas|naudoti automobiliai|"
    # Finnish
    r"autokauppa|autovuokraamo|autonosat|"
    r"autokorjaamo|käytetty auto|rengasliike|"
    # Swedish
    r"bilförsäljare|bilhandlare|biluthyrning|"
    r"bildelar|bilverkstad|begagnade bilar|"
    # Norwegian
    r"bilforhandler|bilutleie|bildeler|bilverksted|"
    r"brukte biler|"
    # Danish
    r"bilforhandler|biludlejning|bildele|"
    r"autoværksted|brugte biler|"
    # Icelandic
    r"bílasala|bílaleiga|bílavarahlutir|"
    # Persian
    r"نمایندگی خودرو|اجاره خودرو|قطعات خودرو|"
    r"تعمیرگاه خودرو|خودرو دست دوم|"
    # Arabic
    r"وكالة سيارات|تأجير سيارات|قطع غيار سيارات|"
    r"ورشة سيارات|سيارات مستعملة|"
    # Hebrew
    r"סוכנות רכב|השכרת רכב|חלפי רכב|"
    r"מוסך|רכבים יד שנייה|"
    # Hindi
    r"कार डीलर|कार किराये|कार पार्ट्स|"
    r"पुरानी कार|कार सर्विस|"
    # Bengali
    r"গাড়ি ডিলার|গাড়ি ভাড়া|গাড়ির যন্ত্রাংশ|"
    # Tamil
    r"கார் வியாபாரி|கார் வாடகை|வாகனப் பாகங்கள்|"
    # Chinese (Simplified and Traditional)
    r"汽车经销商|汽車經銷商|"
    r"汽车租赁|汽車租賃|"
    r"汽车配件|汽車配件|汽车零件|汽車零件|"
    r"汽车维修|汽車維修|二手车|二手車|"
    r"轮胎店|輪胎店|"
    # Japanese
    r"自動車ディーラー|レンタカー|自動車部品|"
    r"自動車整備|中古車|タイヤ販売|"
    # Korean
    r"자동차 대리점|자동차 렌트|렌터카|"
    r"자동차 부품|자동차 정비|중고차|타이어 가게|"
    # Vietnamese
    r"đại lý ô tô|đại lý xe|cho thuê xe ô tô|"
    r"phụ tùng ô tô|sửa chữa ô tô|xe đã qua sử dụng|"
    # Thai
    r"ตัวแทนจำหน่ายรถ|รถเช่า|อะไหล่รถยนต์|"
    r"อู่ซ่อมรถ|รถมือสอง|"
    # Indonesian
    r"dealer mobil|sewa mobil|suku cadang mobil|"
    r"bengkel mobil|mobil bekas|toko ban|"
    # Malay
    r"pengedar kereta|sewa kereta|alat ganti kereta|"
    r"bengkel kereta|kereta terpakai|"
    # Filipino (Tagalog)
    r"dealer ng kotse|paupahang sasakyan|"
    # Catalan
    r"concessionari de cotxes|lloguer de cotxes|"
    r"recanvis d'automòbil|"
    # Galician
    r"concesionario de coches|"
    # Welsh
    r"masnachwr ceir|"
    # Irish
    r"déileálaí gluaisteán|"
    # Afrikaans
    r"motorhandelaar|motorhure|"
    # Macedonian
    r"автокуќа|продажба на автомобили|"
    r"изнајмување автомобили|резервни делови за автомобили|"
    r"автосервис|продавница за гуми|"
    # Belarusian
    r"аўтасалон|аўтадылер|пракат аўтамабіляў|"
    r"аўтазапчасткі|аўтасэрвіс|шынамантаж|"
    # Azerbaijani
    r"avtosalon|avtomobil ticarəti|"
    r"avtomobil icarəsi|avtomobil ehtiyat hissələri|"
    r"avtoservis|təkər mağazası|"
    # Georgian
    r"ავტოსალონი|ავტომობილების გაყიდვა|"
    r"ავტომობილების ქირაობა|ავტო ნაწილები|"
    r"ავტოსერვისი|საბურავების მაღაზია|"
    # Armenian
    r"ավտոսրահ|ավտոմեքենաների վաճառք|"
    r"ավտոմեքենաների վարձույթ|ավտո պահեստամասեր|"
    r"ավտոսերվիս|անվադողերի խանութ|"
    # Kazakh
    r"автосалон|автодилер|"
    r"автокөлік жалға беру|автокөлік қосалқы бөлшектері|"
    r"автосервис|шиналар дүкені|"
    # Uzbek
    r"avtosalon|avtomobil sotuvi|"
    r"avtomobil ijarasi|avtomobil ehtiyot qismlari|"
    r"avtoservis|shinalar do'koni|"
    # Mongolian
    r"автосалон|машин зарах|"
    r"машин түрээслэх|машины сэлбэг|"
    r"автосервис|дугуйн дэлгүүр|"
    # Khmer
    r"ហាងលក់រថយន្ត|ឈ្មួញរថយន្ត|"
    r"ការជួលរថយន្ត|គ្រឿងបន្លាស់រថយន្ត|"
    r"សេវាជួសជុលរថយន្ត|"
    # Burmese
    r"ကားအရောင်းပြခန်း|ကားအငှား|"
    r"ကားအပိုပစ္စည်း|ကားပြုပြင်ရေးဆိုင်|"
    # Lao
    r"ຮ້ານຂາຍລົດ|ການເຊົ່າລົດ|"
    r"ອາໄຫຼ່ລົດ|ຮ້ານຊ່ອມລົດ|"
    # Nepali
    r"कार डिलर|कार किराया|"
    r"कार पुर्जा|कार मरम्मत|"
    # Sinhala
    r"මෝටර් රථ අලෙවියා|මෝටර් රථ කුලී|"
    r"මෝටර් රථ අමතර කොටස්|"
    # Amharic
    r"የመኪና ሻጭ|መኪና ኪራይ|"
    r"የመኪና ዕቃዎች|"
    # Yoruba
    r"olùtà ọkọ̀|ìyalo ọkọ̀|"
    r"ohun-èlò ọkọ̀|"
    # Hausa
    r"mai sayar da motoci|haya motoci|"
    r"kayayyakin mota|gyaran motoci|"
    # Igbo
    r"onye na-ere ụgbọ ala|ịgbazinye ụgbọ ala|"
    r"akụkụ ụgbọ ala|"
    # Zulu
    r"umthengisi wezimoto|ukuqashwa kwezimoto|"
    r"izingxenye zezimoto|ukulungisa izimoto|"
    # Pashto
    r"د موټرو پلورنځی|د موټر کرایه|"
    r"د موټر پرزې|د موټر مرمت|"
    # Kurdish
    r"firotgeha erebeyan|kirêya erebeyan|"
    r"perçeyên erebeyan|servisa erebeyan|"
    # Tajik
    r"автосалон|иҷораи мошин|"
    r"қисмҳои эҳтиётии мошин|таъмири мошин|"
    # Kyrgyz
    r"автосалон|автоунаа ижарасы|"
    r"автоунаа запас бөлүктөрү|автосервис|"
    # Maltese
    r"konċessjonarju tal-karozzi|kiri tal-karozzi|"
    r"spare parts tal-karozzi|workshop tal-karozzi|"
    # Luxembourgish
    r"autohändler|autosvermietung|"
    r"autosersatzdeeler|autoswerkstat|"
    r"reifenhandel|"
    # Haitian Creole
    r"machann oto|lokasyon oto|"
    r"pyès oto|garaj reparasyon oto|"
    # Frisian
    r"autodealer|autoferhier|"
    r"auto-ûnderdielen|garaazje|"
    # Yiddish
    r"קאַר פאַרקויפער|קאַר רענטאַל|"
    # Faroese
    r"bilasøla|bilaleiga|"
    # Tatar
    r"автосалон|машина прокаты|"
    r"машина әйберләре|"
    # Javanese
    r"dealer mobil|sewa mobil|"
    r"onderdil mobil|bengkel mobil|"
    # Sundanese
    r"dealer mobil|sewa mobil|"
    # Cebuano
    r"dealer sa awto|abang sa awto|"
    r"piyesa sa awto|talyer sa awto"
    r")\b"
)

# Entertainment — TV/film production, music labels, gaming, streaming
ENTERTAINMENT_RE = re.compile(
    r"(?i)\b("
    # English
    r"film production|movie studio|production studio|"
    r"television production|tv production|tv group|"
    r"music label|record label|recording studio|"
    r"video games?|gaming studio|game development|"
    r"streaming service|on-demand video|"
    r"animation studio|post[- ]?production|"
    # Spanish
    r"productora cinematográfica|productora audiovisual|"
    r"sello discográfico|casa discográfica|discográfica|"
    r"estudio de grabación|estudio de animación|"
    r"videojuegos|desarrollo de videojuegos|estudio de videojuegos|"
    r"servicio de streaming|plataforma de streaming|postproducción|"
    # Portuguese
    r"casa de produção|estúdio de gravação|gravadora|"
    r"jogos eletrônicos|estúdio de jogos|desenvolvimento de jogos|"
    r"serviço de streaming|estúdio de animação|pós-produção|"
    # Italian
    r"casa di produzione|etichetta discografica|"
    r"studio di registrazione|videogiochi|sviluppo videogiochi|"
    r"servizio di streaming|studio di animazione|post-produzione|"
    # French
    r"production cinéma|production audiovisuelle|"
    r"maison de disques|studio d'enregistrement|"
    r"jeux vidéo|développement de jeux|"
    r"service de streaming|studio d'animation|post-production|"
    # German
    r"filmproduktion|musikverlag|plattenfirma|plattenlabel|"
    r"tonstudio|videospiele|spieleentwicklung|"
    r"streaming[- ]?dienst|animationsstudio|"
    # Dutch
    r"filmproductie|platenmaatschappij|"
    r"opnamestudio|videospellen|spelontwikkeling|"
    r"streamingdienst|animatiestudio|"
    # Russian
    r"кино студия|кинокомпания|музыкальный лейбл|"
    r"студия звукозаписи|видеоигры|разработка игр|"
    r"стриминговый сервис|студия анимации|"
    # Ukrainian
    r"кінокомпанія|студія звукозапису|відеоігри|розробка ігор|"
    # Polish
    r"wytwórnia filmowa|wytwórnia muzyczna|"
    r"studio nagraniowe|gry komputerowe|gry wideo|"
    r"produkcja gier|serwis streamingowy|studio animacji|"
    # Czech
    r"filmová produkce|vydavatelství hudby|"
    r"nahrávací studio|videohry|vývoj her|"
    r"streamovací služba|animační studio|"
    # Slovak
    r"filmová produkcia|hudobné vydavateľstvo|"
    r"nahrávacie štúdio|videohry|vývoj hier|"
    r"streamovacia služba|animačné štúdio|"
    # Hungarian
    r"filmstúdió|lemezkiadó|hangstúdió|"
    r"videojáték|játékfejlesztés|"
    r"streamingszolgáltatás|animációs stúdió|"
    # Romanian
    r"studio de producție|casă de discuri|"
    r"studio de înregistrări|jocuri video|dezvoltare jocuri|"
    r"serviciu de streaming|studio de animație|"
    # Bulgarian
    r"филмово студио|звукозаписно студио|видеоигри|"
    # Croatian / Serbian / Bosnian
    r"filmska produkcija|diskografska kuća|"
    r"studio za snimanje|videoigre|razvoj igara|"
    r"streaming servis|"
    # Slovenian
    r"filmska produkcija|glasbena založba|"
    r"snemalni studio|videoigre|razvoj iger|"
    # Albanian
    r"prodhim filmi|shtëpi diskografike|"
    r"studio incizimi|lojëra video|"
    # Greek
    r"εταιρεία παραγωγής|δισκογραφική εταιρεία|"
    r"στούντιο ηχογράφησης|βιντεοπαιχνίδια|ανάπτυξη παιχνιδιών|"
    r"υπηρεσία streaming|στούντιο κινουμένων σχεδίων|"
    # Turkish
    r"film yapım şirketi|plak şirketi|müzik şirketi|"
    r"ses kayıt stüdyosu|video oyun|oyun geliştirme|"
    r"yayın hizmeti|animasyon stüdyosu|"
    # Estonian
    r"filmiproduktsioon|plaadifirma|helistuudio|"
    r"videomängud|mängude arendus|"
    # Latvian
    r"filmu producēšana|ierakstu kompānija|ieraksta studija|"
    r"videospēles|spēļu izstrāde|"
    # Lithuanian
    r"kino studija|įrašų kompanija|įrašų studija|"
    r"vaizdo žaidimai|žaidimų kūrimas|"
    # Finnish
    r"elokuvatuotanto|levy-yhtiö|äänitysstudio|"
    r"videopelit|pelinkehitys|suoratoistopalvelu|"
    # Swedish
    r"filmproduktion|skivbolag|inspelningsstudio|"
    r"datorspel|tv-spel|spelutveckling|"
    r"streamingtjänst|animationsstudio|"
    # Norwegian
    r"filmproduksjon|plateselskap|innspillingsstudio|"
    r"videospill|spillutvikling|"
    r"strømmetjeneste|animasjonsstudio|"
    # Danish
    r"filmproduktion|pladeselskab|indspilningsstudie|"
    r"videospil|spiludvikling|"
    r"streamingtjeneste|animationsstudie|"
    # Icelandic
    r"kvikmyndaframleiðsla|hljómplötuútgáfa|hljóðver|"
    r"tölvuleikir|"
    # Persian
    r"شرکت فیلمسازی|شرکت موسیقی|استودیو ضبط|"
    r"بازی ویدئویی|توسعه بازی|"
    # Arabic
    r"شركة إنتاج سينمائي|شركة تسجيلات موسيقية|"
    r"استوديو تسجيل|ألعاب فيديو|تطوير الألعاب|"
    r"خدمة بث|استوديو رسوم متحركة|"
    # Hebrew
    r"חברת הפקה|חברת תקליטים|אולפן הקלטות|"
    r"משחקי וידאו|פיתוח משחקים|"
    r"שירות סטרימינג|אולפן אנימציה|"
    # Hindi
    r"फिल्म निर्माण|संगीत कंपनी|रिकॉर्डिंग स्टूडियो|"
    r"वीडियो गेम|गेम डेवलपमेंट|"
    # Bengali
    r"চলচ্চিত্র প্রযোজনা|রেকর্ডিং স্টুডিও|ভিডিও গেম|"
    # Tamil
    r"திரைப்பட தயாரிப்பு|பதிவு அறை|"
    # Chinese (Simplified and Traditional)
    r"电影制作|电影公司|電影製作|電影公司|"
    r"游戏开发|遊戲開發|"
    r"唱片公司|唱片廠牌|"
    r"录音棚|錄音室|"
    r"视频游戏|電子遊戲|電玩遊戲|"
    r"流媒体服务|串流服務|"
    r"动画工作室|動畫工作室|"
    # Japanese
    r"映画制作|ゲーム開発|アニメ制作|"
    r"レコード会社|録音スタジオ|ビデオゲーム|"
    r"ストリーミングサービス|アニメーションスタジオ|"
    # Korean
    r"영화 제작|게임 개발|"
    r"음반 회사|레코드 레이블|녹음 스튜디오|"
    r"비디오 게임|스트리밍 서비스|애니메이션 스튜디오|"
    # Vietnamese
    r"công ty sản xuất phim|hãng đĩa|"
    r"phòng thu âm|trò chơi điện tử|phát triển trò chơi|"
    r"dịch vụ phát trực tuyến|xưởng phim hoạt hình|"
    # Thai
    r"บริษัทผลิตภาพยนตร์|ค่ายเพลง|สตูดิโออัดเสียง|"
    r"วิดีโอเกม|พัฒนาเกม|"
    # Indonesian
    r"produksi film|label rekaman|studio rekaman|"
    r"video game|pengembangan game|layanan streaming|"
    # Malay
    r"penerbitan filem|syarikat rakaman|studio rakaman|"
    r"video game|pembangunan permainan|"
    # Catalan
    r"productora cinematogràfica|discogràfica|"
    r"estudi de gravació|videojocs|"
    # Welsh
    r"cwmni cynhyrchu ffilmiau|gemau fideo|"
    # Macedonian
    r"филмска продукција|музичка куќа|"
    r"студио за снимање|видеоигри|"
    r"стрим сервис|"
    # Belarusian
    r"кінастудыя|музычны лэйбл|"
    r"студыя гуказапісу|відэагульні|"
    # Azerbaijani
    r"film prodüksiyası|musiqi etiketi|"
    r"səs yazma studiyası|video oyunlar|"
    r"yayım xidməti|animasiya studiyası|"
    # Georgian
    r"ფილმწარმოება|მუსიკალური ლეიბლი|"
    r"ჩაწერის სტუდია|ვიდეო თამაშები|"
    r"სტრიმინგ მომსახურება|ანიმაციის სტუდია|"
    # Armenian
    r"ֆիլմարտադրություն|ձայնագրման ստուդիա|"
    r"վիդեո խաղեր|"
    r"հոսքային ծառայություն|անիմացիոն ստուդիա|"
    # Kazakh
    r"кино студия|жазба студиясы|"
    r"бейнеойындар|стриминг қызметі|"
    r"анимация студиясы|"
    # Uzbek
    r"film studiyasi|yozish studiyasi|"
    r"video o'yinlar|striming xizmati|"
    r"animatsiya studiyasi|"
    # Mongolian
    r"кино студи|дуу бичлэгийн студи|"
    r"видео тоглоом|"
    # Khmer
    r"ផលិតកម្មភាពយន្ត|ស្ទូឌីយោថត|"
    r"ហ្គេមវីដេអូ|សេវាបញ្ចាំ|"
    # Burmese
    r"ရုပ်ရှင်ထုတ်လုပ်ရေး|အသံသွင်းစတူဒီယို|"
    r"ဗီဒီယိုဂိမ်း|"
    # Lao
    r"ການຜະລິດໜັງ|ສະຕູດິໂອບັນທຶກ|"
    r"ເກມວີດີໂອ|ການບໍລິການສະຕຣີມມິງ|"
    # Nepali
    r"फिल्म निर्माण|रेकर्डिङ स्टुडियो|"
    r"भिडियो गेम|स्ट्रिमिङ सेवा|"
    # Sinhala
    r"චිත්‍රපට නිෂ්පාදනය|පටිගත කිරීමේ ස්ටුඩියෝව|"
    r"වීඩියෝ ක්‍රීඩා|ප්‍රවාහ සේවාව|"
    # Amharic
    r"የፊልም ምርት|የቀረጻ ስቱዲዮ|"
    r"ቪዲዮ ጨዋታ|"
    # Yoruba
    r"ìmúrasílẹ̀ fíìmù|ilé ìgbasílẹ̀ orin|"
    r"eré fídíò|"
    # Hausa
    r"masana'antar fim|kamfanin rikodi|"
    r"wasannin bidiyo|"
    # Igbo
    r"nrụpụta ihe nkiri|ụlọ ihe ndekọ|"
    r"egwuregwu vidiyo|"
    # Zulu
    r"ukukhiqizwa kwefilimu|isitudiyo sokuqopha|"
    r"imidlalo yevidiyo|"
    # Pashto
    r"د فلم تولید|د ثبت سټوډیو|"
    r"د ویډیو لوبې|"
    # Kurdish
    r"hilberîna fîlman|stûdyoya tomarê|"
    r"lîstikên vîdyoyê|servisa stîrîmingê|"
    # Tajik
    r"истеҳсоли филм|студияи сабт|"
    r"бозиҳои видеоӣ|хадамоти стриминг|"
    # Kyrgyz
    r"кино тартуу|жаздыруу студиясы|"
    r"видео оюндар|"
    # Maltese
    r"produzzjoni ta' films|stuldju tar-rekordings|"
    r"video games|servizz ta' streaming|"
    r"stuldju tal-animazzjoni|"
    # Luxembourgish
    r"filmproduktioun|opnamestudio|"
    r"videospiller|streaming dénger|"
    r"animatiounsstudio|"
    # Haitian Creole
    r"pwodiksyon fim|estidyo enrejistreman|"
    r"jwèt videyo|sèvis stiminng|"
    # Frisian
    r"filmproduksje|opnamestudio|"
    r"fideospultsjes|"
    # Yiddish
    r"פילם פראָדוקציע|רעקאָרדינג סטודיאָ|"
    r"ווידעא ספילן|"
    # Faroese
    r"filmsframleiðsla|innspælingarstova|"
    # Tatar
    r"кино җитештерү|видеоуен|"
    # Javanese
    r"produksi film|studio rekaman|"
    r"video game|"
    # Sundanese
    r"produksi film|video game|"
    # Cebuano
    r"produksyon sa pelikula|estudyo sa rekord|"
    r"video games|serbisyo sa streaming"
    r")\b"
)

# Higher-precedence categories per README (these win over ISP / Web Host /
# etc. when they match):

# Email Security — anti-spam / anti-phishing / threat intel
EMAIL_SECURITY_RE = re.compile(
    r"(?i)\b("
    # English
    r"email security|anti[ -]?spam|spam filter(?:ing)?|"
    r"phishing protection|anti[ -]?phishing|"
    r"email threat (?:protection|intelligence)|"
    r"email gateway|secure email gateway|seg\b|"
    r"email defense|email protection platform|"
    # Spanish
    r"seguridad del correo electrónico|"
    r"protección antiphishing|protección contra phishing|"
    r"filtro antispam|protección de correo|"
    # Portuguese
    r"segurança de e?mail|proteção contra phishing|"
    r"filtro antispam|proteção de e?mail|"
    # French
    r"sécurité des e?mails|sécurité de la messagerie|"
    r"protection anti[- ]?phishing|filtre anti[- ]?spam|"
    r"protection de la messagerie|"
    # Italian
    r"sicurezza e?mail|sicurezza della posta elettronica|"
    r"protezione anti[- ]?phishing|filtro anti[- ]?spam|"
    # German
    r"e?mail[- ]?sicherheit|phishing[- ]?schutz|"
    r"spam[- ]?filter|spamschutz|"
    # Dutch
    r"e?mailbeveiliging|antiphishing|antispam|"
    # Polish
    r"bezpieczeństwo poczty|ochrona przed phishingiem|"
    r"filtr antyspamowy|"
    # Czech
    r"zabezpečení e?mailu|ochrana před phishingem|"
    r"antispamový filtr|"
    # Russian
    r"защита электронной почты|защита от фишинга|"
    r"антиспам|спам[- ]?фильтр|защита почты|"
    # Ukrainian
    r"захист електронної пошти|антиспам|"
    # Turkish
    r"e?posta güvenliği|kimlik avı koruması|"
    r"anti[- ]?spam|spam filtresi|"
    # Greek
    r"ασφάλεια e?mail|προστασία από phishing|"
    r"φίλτρο ανεπιθύμητης αλληλογραφίας|"
    # Romanian
    r"securitate e?mail|protecție anti[- ]?phishing|"
    r"filtru anti[- ]?spam|"
    # Hungarian
    r"e?mail biztonság|adathalászat elleni védelem|"
    # Arabic
    r"أمن البريد الإلكتروني|الحماية من التصيد|"
    r"مكافحة البريد العشوائي|"
    # Hebrew
    r"אבטחת דואר אלקטרוני|הגנה מפני פישינג|"
    r"סינון דואר זבל|"
    # Persian
    r"امنیت ایمیل|محافظت در برابر فیشینگ|"
    # Chinese (Simplified and Traditional)
    r"电子邮件安全|電子郵件安全|"
    r"反垃圾邮件|反垃圾郵件|"
    r"反钓鱼|反釣魚|防钓鱼|防釣魚|"
    r"邮件安全网关|郵件安全閘道|"
    # Japanese
    r"メールセキュリティ|フィッシング対策|"
    r"迷惑メール対策|スパム対策|"
    # Korean
    r"이메일 보안|피싱 방지|스팸 차단|"
    # Vietnamese
    r"bảo mật e?mail|chống lừa đảo|chống thư rác|"
    # Indonesian
    r"keamanan e?mail|perlindungan phishing|"
    # Thai
    r"ความปลอดภัยอีเมล|ป้องกันฟิชชิ่ง|"
    # Macedonian
    r"безбедност на е-пошта|заштита од фишинг|"
    r"филтер против спам|"
    # Belarusian
    r"бяспека электроннай пошты|абарона ад фішынгу|"
    r"антыспам фільтр|"
    # Azerbaijani
    r"e-poçt təhlükəsizliyi|fişinqdən qorunma|"
    r"anti-spam filtri|"
    # Georgian
    r"ელ-ფოსტის უსაფრთხოება|ფიშინგის წინააღმდეგ დაცვა|"
    r"ანტი-სპამ ფილტრი|"
    # Armenian
    r"էլեկտրոնային փոստի անվտանգություն|ֆիշինգից պաշտպանություն|"
    r"հակասպամ զտիչ|"
    # Kazakh
    r"электрондық пошта қауіпсіздігі|фишингтен қорғау|"
    r"спамға қарсы сүзгі|"
    # Uzbek
    r"e-pochta xavfsizligi|fishingdan himoya|"
    r"spamga qarshi filtr|"
    # Mongolian
    r"имэйлийн аюулгүй байдал|фишингээс хамгаалах|"
    # Khmer
    r"សុវត្ថិភាពអ៊ីមែល|ការការពារពីការបន្លំ|"
    # Burmese
    r"အီးမေးလ် လုံခြုံရေး|ဖစ်ရှင်း ကာကွယ်ရေး|"
    # Lao
    r"ຄວາມປອດໄພ ອີເມລ|ການປ້ອງກັນຟິສຊິງ|"
    # Nepali
    r"इमेल सुरक्षा|फिशिङबाट सुरक्षा|"
    # Sinhala
    r"විද්‍යුත් තැපැල් ආරක්ෂාව|ෆිෂින් ආරක්ෂාව|"
    # Amharic
    r"የኢሜል ደህንነት|ከማታለል ጥበቃ|"
    # Yoruba
    r"ààbò ímẹ́ẹ̀lì|ààbò lọ́wọ́ ìjáfáfá|"
    # Hausa
    r"tsaron imel|kariya daga zamba|"
    # Zulu
    r"ukuvikeleka kwe-imeyili|ukuvikela ekuthumeleni okukhohlisayo|"
    # Pashto
    r"د بریښنالیک امنیت|د فشینګ څخه ساتنه|"
    # Kurdish
    r"ewlehiya e-name|parastina ji phîşîngê|"
    # Tajik
    r"амнияти почтаи электронӣ|ҳифз аз фишинг|"
    # Kyrgyz
    r"электрондук кат коопсуздугу|фишингден коргоо|"
    # Maltese
    r"sigurtà tal-email|protezzjoni mill-phishing|"
    r"filtru kontra l-ispam|"
    # Luxembourgish
    r"e-mail sécherheet|phishing schutz|"
    r"spam filter|"
    # Haitian Creole
    r"sekirite imèl|pwoteksyon kont fishing|"
    # Frisian
    r"e-mailfeiligens|phishing-beskerming|"
    # Javanese
    r"keamanan email|perlindungan phishing|"
    # Cebuano
    r"seguridad sa email|proteksyon batok phishing"
    r")\b"
)

# Marketing — agencies, marketing platforms, ad tech
MARKETING_RE = re.compile(
    r"(?i)\b("
    # English
    r"marketing platform|marketing automation|"
    r"email marketing|sms marketing|"
    r"marketing agency|advertising agency|ad agency|"
    r"digital marketing|inbound marketing|"
    r"marketing cloud|martech|"
    # Spanish
    r"agencia de marketing|agencia de publicidad|"
    r"marketing digital|automatización de marketing|"
    r"plataforma de marketing|email marketing|marketing por correo|"
    # Portuguese
    r"agência de marketing|agência de publicidade|"
    r"marketing digital|automação de marketing|"
    r"plataforma de marketing|email marketing|marketing por e?mail|"
    # French
    r"agence de marketing|agence de publicité|"
    r"agence de communication|marketing numérique|"
    r"automatisation marketing|plateforme marketing|"
    r"e?mailing|marketing par e?mail|"
    # Italian
    r"agenzia di marketing|agenzia pubblicitaria|"
    r"marketing digitale|automazione marketing|"
    r"piattaforma di marketing|"
    # German
    r"marketingagentur|werbeagentur|kommunikationsagentur|"
    r"digitalmarketing|marketing[- ]?automation|"
    r"marketingplattform|e?mail[- ]?marketing|"
    # Dutch
    r"marketingbureau|reclamebureau|"
    r"digitale marketing|"
    # Polish
    r"agencja marketingowa|agencja reklamowa|"
    r"marketing cyfrowy|automatyzacja marketingu|"
    r"platforma marketingowa|e?mail marketing|"
    # Czech
    r"marketingová agentura|reklamní agentura|"
    r"digitální marketing|automatizace marketingu|"
    # Slovak
    r"marketingová agentúra|reklamná agentúra|"
    r"digitálny marketing|"
    # Russian
    r"маркетинговое агентство|рекламное агентство|"
    r"цифровой маркетинг|автоматизация маркетинга|"
    r"платформа для маркетинга|e?mail[- ]маркетинг|"
    # Ukrainian
    r"маркетингове агентство|рекламне агентство|"
    r"цифровий маркетинг|"
    # Turkish
    r"pazarlama ajansı|reklam ajansı|"
    r"dijital pazarlama|pazarlama otomasyonu|"
    r"e?posta pazarlama|pazarlama platformu|"
    # Greek
    r"εταιρεία μάρκετινγκ|διαφημιστική εταιρεία|"
    r"ψηφιακό μάρκετινγκ|"
    # Romanian
    r"agenție de marketing|agenție de publicitate|"
    r"marketing digital|automatizare marketing|"
    # Hungarian
    r"marketingügynökség|reklámügynökség|"
    r"digitális marketing|marketingautomatizálás|"
    # Bulgarian
    r"маркетингова агенция|рекламна агенция|"
    r"дигитален маркетинг|"
    # Croatian / Serbian / Bosnian
    r"marketinška agencija|reklamna agencija|"
    r"digitalni marketing|"
    # Slovenian
    r"marketinška agencija|oglaševalska agencija|"
    r"digitalni marketing|"
    # Estonian
    r"turundusagentuur|reklaamiagentuur|"
    r"digiturundus|"
    # Finnish
    r"markkinointitoimisto|mainostoimisto|"
    r"digitaalinen markkinointi|"
    # Swedish
    r"marknadsföringsbyrå|reklambyrå|"
    r"digital marknadsföring|"
    # Norwegian
    r"markedsføringsbyrå|reklamebyrå|"
    r"digital markedsføring|"
    # Danish
    r"marketingbureau|reklamebureau|"
    r"digital markedsføring|"
    # Persian
    r"آژانس بازاریابی|آژانس تبلیغاتی|"
    r"بازاریابی دیجیتال|"
    # Arabic
    r"وكالة تسويق|وكالة إعلانات|"
    r"التسويق الرقمي|أتمتة التسويق|"
    r"التسويق عبر البريد الإلكتروني|"
    # Hebrew
    r"סוכנות שיווק|סוכנות פרסום|"
    r"שיווק דיגיטלי|אוטומציה שיווקית|"
    # Hindi
    r"मार्केटिंग एजेंसी|विज्ञापन एजेंसी|"
    r"डिजिटल मार्केटिंग|"
    # Bengali
    r"মার্কেটিং এজেন্সি|বিজ্ঞাপন সংস্থা|"
    # Chinese (Simplified and Traditional)
    r"营销平台|營銷平台|广告公司|廣告公司|"
    r"营销公司|營銷公司|"
    r"数字营销|數位行銷|"
    r"营销自动化|行銷自動化|"
    r"邮件营销|電郵行銷|"
    # Japanese
    r"マーケティング会社|広告代理店|"
    r"デジタルマーケティング|"
    r"マーケティングオートメーション|"
    r"メールマーケティング|"
    # Korean
    r"마케팅 플랫폼|마케팅 회사|광고 대행사|"
    r"디지털 마케팅|마케팅 자동화|이메일 마케팅|"
    # Vietnamese
    r"công ty tiếp thị|công ty quảng cáo|"
    r"tiếp thị kỹ thuật số|tự động hóa tiếp thị|"
    # Thai
    r"บริษัทการตลาด|เอเจนซี่โฆษณา|"
    r"การตลาดดิจิทัล|"
    # Indonesian
    r"agensi pemasaran|agensi periklanan|"
    r"pemasaran digital|otomasi pemasaran|"
    # Malay
    r"agensi pemasaran|agensi pengiklanan|"
    r"pemasaran digital|"
    # Catalan
    r"agència de màrqueting|agència de publicitat|"
    # Macedonian
    r"маркетинг агенција|рекламна агенција|"
    r"дигитален маркетинг|маркетинг автоматизација|"
    r"е-маил маркетинг|маркетинг платформа|"
    # Belarusian
    r"маркетынгавае агенцтва|рэкламнае агенцтва|"
    r"лічбавы маркетынг|аўтаматызацыя маркетынгу|"
    # Azerbaijani
    r"marketinq agentliyi|reklam agentliyi|"
    r"rəqəmsal marketinq|marketinq avtomatlaşdırılması|"
    r"e-poçt marketinqi|marketinq platforması|"
    # Georgian
    r"მარკეტინგული სააგენტო|სარეკლამო სააგენტო|"
    r"ციფრული მარკეტინგი|მარკეტინგის ავტომატიზაცია|"
    r"ელ-ფოსტის მარკეტინგი|მარკეტინგ პლატფორმა|"
    # Armenian
    r"մարքեթինգային գործակալություն|գովազդային գործակալություն|"
    r"թվային մարքեթինգ|մարքեթինգի ավտոմատացում|"
    r"էլեկտրոնային փոստի մարքեթինգ|"
    # Kazakh
    r"маркетинг агенттігі|жарнама агенттігі|"
    r"цифрлық маркетинг|маркетингті автоматтандыру|"
    r"e-mail маркетинг|"
    # Uzbek
    r"marketing agentligi|reklama agentligi|"
    r"raqamli marketing|marketing avtomatlashtirish|"
    r"e-pochta marketingi|"
    # Mongolian
    r"маркетинг агентлаг|сурталчилгааны агентлаг|"
    r"дижитал маркетинг|"
    # Khmer
    r"ភ្នាក់ងារទីផ្សារ|ភ្នាក់ងារផ្សាយពាណិជ្ជកម្ម|"
    r"ការទីផ្សារឌីជីថល|"
    # Burmese
    r"စျေးကွက်ရှာဖွေရေး အေဂျင်စီ|ကြော်ငြာ အေဂျင်စီ|"
    r"ဒီဂျစ်တယ် စျေးကွက်ရှာဖွေရေး|"
    # Lao
    r"ບໍລິສັດການຕະຫຼາດ|ບໍລິສັດໂຄສະນາ|"
    r"ການຕະຫຼາດດິຈິຕອລ|"
    # Nepali
    r"मार्केटिङ एजेन्सी|विज्ञापन एजेन्सी|"
    r"डिजिटल मार्केटिङ|"
    # Sinhala
    r"අලෙවිකරණ ආයතනය|දැන්වීම් ආයතනය|"
    r"ඩිජිටල් අලෙවිකරණය|"
    # Amharic
    r"የግብይት ኤጀንሲ|የማስታወቂያ ኤጀንሲ|"
    r"ዲጂታል ግብይት|"
    # Yoruba
    r"ilé iṣẹ́ ìpolówó|ilé iṣẹ́ pípèsè|"
    # Hausa
    r"kamfanin tallace-tallace|kamfanin talla|"
    r"talla na zamani|"
    # Igbo
    r"ụlọ ọrụ ahịa ngosi|ụlọ ọrụ mgbasa ozi|"
    # Zulu
    r"i-ejensi yokumaketha|i-ejensi yokukhangisa|"
    r"ukumaketha kwedijithali|"
    # Pashto
    r"د بازارموندنې اداره|د اعلان اداره|"
    r"ډیجیټل مارکیټینګ|"
    # Kurdish
    r"navenda bazirganiyê|navenda reklamê|"
    r"bazirganiya dîjîtal|"
    # Tajik
    r"агентии маркетинг|агентии реклама|"
    r"маркетинги рақамӣ|"
    # Kyrgyz
    r"маркетинг агенттиги|жарнама агенттиги|"
    r"санариптик маркетинг|"
    # Maltese
    r"aġenzija tal-marketing|aġenzija tar-reklamar|"
    r"marketing diġitali|awtomazzjoni tal-marketing|"
    # Luxembourgish
    r"marketinagentur|reklamenagentur|"
    r"digital marketing|marketingplattform|"
    # Haitian Creole
    r"ajans maketing|ajans piblisite|"
    r"maketing dijital|"
    # Frisian
    r"marketingbureau|reklamburo|"
    r"digitale marketing|"
    # Yiddish
    r"מאַרקעטינג אגענטור|רעקלאַמע אגענטור|"
    # Faroese
    r"marknaðarstova|lýsingarstova|"
    # Tatar
    r"маркетинг агентлыгы|реклама агентлыгы|"
    # Javanese
    r"agensi pemasaran|agensi periklanan|"
    r"pemasaran digital|"
    # Sundanese
    r"agénsi pemasaran|"
    # Cebuano
    r"ahensya sa marketing|ahensya sa pag-anunsyo|"
    r"digital nga marketing"
    r")\b"
)

# Email Provider
EMAIL_PROVIDER_RE = re.compile(
    r"(?i)\b("
    # English
    r"email hosting|business email|professional email|"
    r"webmail provider|email service provider|"
    r"mailbox hosting|hosted email|"
    # Spanish
    r"proveedor de correo|alojamiento de correo|"
    r"correo empresarial|correo profesional|"
    r"hospedaje de correo|"
    # Portuguese
    r"provedor de e?mail|hospedagem de e?mail|"
    r"e?mail empresarial|e?mail profissional|"
    # French
    r"fournisseur de messagerie|hébergement de messagerie|"
    r"messagerie professionnelle|messagerie d'entreprise|"
    r"webmail professionnel|"
    # Italian
    r"servizio e?mail|hosting e?mail|"
    r"e?mail aziendale|e?mail professionale|"
    # German
    r"e?mail[- ]?provider|e?mail[- ]?hosting|"
    r"geschäfts[- ]?e?mail|business[- ]?e?mail|"
    r"webmail[- ]?anbieter|"
    # Dutch
    r"e?mailprovider|e?mailhosting|zakelijke e?mail|"
    # Polish
    r"poczta firmowa|hosting poczty|"
    r"dostawca poczty|"
    # Czech
    r"e?mail hosting|firemní e?mail|profesionální e?mail|"
    # Slovak
    r"e?mailový hosting|firemný e?mail|"
    # Russian
    r"почтовый провайдер|хостинг электронной почты|"
    r"корпоративная почта|деловая почта|"
    # Ukrainian
    r"поштовий провайдер|корпоративна пошта|"
    # Turkish
    r"e?posta sağlayıcı|e?posta barındırma|"
    r"kurumsal e?posta|profesyonel e?posta|"
    # Greek
    r"πάροχος e?mail|φιλοξενία e?mail|"
    r"εταιρικό e?mail|"
    # Romanian
    r"furnizor de e?mail|găzduire e?mail|"
    r"e?mail de afaceri|"
    # Hungarian
    r"e?mail szolgáltató|e?mail hosting|"
    r"céges e?mail|üzleti e?mail|"
    # Persian
    r"هاست ایمیل|ارائه دهنده ایمیل|ایمیل سازمانی|"
    # Arabic
    r"مزود البريد الإلكتروني|استضافة البريد الإلكتروني|"
    r"بريد إلكتروني للأعمال|"
    # Hebrew
    r"ספק דואר אלקטרוני|אחסון דואר אלקטרוני|"
    r"דואר אלקטרוני עסקי|"
    # Chinese (Simplified and Traditional)
    r"邮件服务|郵件服務|"
    r"企业邮箱|企業郵箱|"
    r"商务邮箱|商務郵箱|"
    r"邮件托管|郵件託管|"
    # Japanese
    r"メールホスティング|ビジネスメール|"
    r"メールサービスプロバイダ|"
    # Korean
    r"이메일 호스팅|비즈니스 이메일|기업 이메일|"
    # Vietnamese
    r"dịch vụ e?mail|e?mail doanh nghiệp|lưu trữ e?mail|"
    # Indonesian
    r"penyedia e?mail|hosting e?mail|e?mail bisnis|"
    # Malay
    r"penyedia e?mel|pengehosan e?mel|"
    # Thai
    r"ผู้ให้บริการอีเมล|อีเมลธุรกิจ|"
    # Macedonian
    r"провајдер на е-пошта|хостинг на е-пошта|"
    r"деловна е-пошта|"
    # Belarusian
    r"паштовы правайдар|карпаратыўная пошта|"
    # Azerbaijani
    r"e-poçt provayderi|korporativ e-poçt|"
    r"e-poçt yerləşdirmə|"
    # Georgian
    r"ელ-ფოსტის პროვაიდერი|კორპორატიული ელ-ფოსტა|"
    r"ელ-ფოსტის ჰოსტინგი|"
    # Armenian
    r"էլեկտրոնային փոստի մատակարար|"
    r"կորպորատիվ էլեկտրոնային փոստ|"
    # Kazakh
    r"электрондық пошта провайдері|корпоративтік пошта|"
    # Uzbek
    r"elektron pochta provayderi|korporativ pochta|"
    # Mongolian
    r"имэйл үйлчилгээ үзүүлэгч|корпорацийн имэйл|"
    # Khmer
    r"អ្នកផ្តល់សេវាអ៊ីមែល|អ៊ីមែលអាជីវកម្ម|"
    # Burmese
    r"အီးမေးလ် ပံ့ပိုးသူ|လုပ်ငန်းသုံး အီးမေးလ်|"
    # Lao
    r"ຜູ້ໃຫ້ບໍລິການ ອີເມລ|ອີເມລທຸລະກິດ|"
    # Nepali
    r"इमेल सेवा प्रदायक|व्यवसायिक इमेल|"
    # Sinhala
    r"විද්‍යුත් තැපැල් සේවා සපයන්නා|ව්‍යාපාරික විද්‍යුත් තැපැල|"
    # Amharic
    r"የኢሜል አቅራቢ|የንግድ ኢሜል|"
    # Yoruba
    r"olùpèsè ímẹ́ẹ̀lì|ímẹ́ẹ̀lì òwò|"
    # Hausa
    r"mai bayar da imel|imel na kasuwanci|"
    # Zulu
    r"umhlinzeki we-imeyili|i-imeyili yebhizinisi|"
    # Pashto
    r"د بریښنالیک تأمینوونکی|سوداگریز بریښنالیک|"
    # Kurdish
    r"pêşkêşkarê e-nameyê|e-nameya karûbarê|"
    # Tajik
    r"провайдери почтаи электронӣ|почтаи корпоративӣ|"
    # Kyrgyz
    r"электрондук кат провайдери|корпоративдик кат|"
    # Maltese
    r"fornitur tal-email|email tan-negozju|"
    r"hosting tal-email|"
    # Luxembourgish
    r"e-mail provider|geschäfts e-mail|"
    r"e-mail hosting|"
    # Haitian Creole
    r"founisè imèl|imèl biznis|"
    # Frisian
    r"e-mailprovider|saaklik e-mail|"
    # Javanese
    r"penyedia email|email bisnis|"
    # Cebuano
    r"tighatag sa email|email sa negosyo"
    r")\b"
)

# Lower-precedence (industry-tier) categories. Each detector below has its
# multilingual alternatives grouped one comment per language.

AGRICULTURE_RE = re.compile(
    r"(?i)\b("
    # English
    r"agriculture|agricultural|agribusiness|farming|"
    r"crop production|livestock|"
    r"farm equipment|farm products|"
    r"dairy farming|poultry farming|cattle ranching|"
    r"agricultural cooperative|"
    # Spanish
    r"agricultura|agroindustria|ganadería|"
    r"cooperativa agrícola|empresa agrícola|"
    r"explotación agrícola|productos agrícolas|"
    r"avicultura|cultivos agrícolas|"
    # Portuguese
    r"agronegócio|agropecuária|agricultura|"
    r"cooperativa agrícola|produtos agrícolas|"
    r"pecuária|avicultura|laticínios|"
    r"empresa agrícola|"
    # French
    r"agriculture|agroalimentaire|exploitation agricole|"
    r"coopérative agricole|élevage|"
    r"produits agricoles|aviculture|"
    # Italian
    r"agricoltura|allevamento|"
    r"cooperativa agricola|prodotti agricoli|"
    r"avicoltura|"
    # German
    r"landwirtschaft|agrarwirtschaft|"
    r"landwirtschaftliche genossenschaft|tierhaltung|"
    r"landwirtschaftliche produkte|geflügelzucht|"
    r"viehwirtschaft|"
    # Dutch
    r"landbouw|veeteelt|tuinbouw|"
    r"landbouwcoöperatie|landbouwproducten|pluimveehouderij|"
    # Polish
    r"rolnictwo|hodowla bydła|hodowla drobiu|"
    r"spółdzielnia rolnicza|produkty rolne|"
    r"gospodarstwo rolne|"
    # Czech
    r"zemědělství|chov dobytka|chov drůbeže|"
    r"zemědělské družstvo|zemědělské produkty|"
    # Slovak
    r"poľnohospodárstvo|chov dobytka|chov hydiny|"
    r"poľnohospodárske družstvo|"
    # Russian
    r"сельское хозяйство|агропромышленность|"
    r"животноводство|птицеводство|"
    r"сельскохозяйственный кооператив|"
    r"сельскохозяйственная продукция|"
    r"растениеводство|молочное производство|"
    # Ukrainian
    r"сільське господарство|тваринництво|"
    r"птахівництво|сільськогосподарська продукція|"
    # Bulgarian
    r"земеделие|животновъдство|птицевъдство|"
    r"земеделска кооперация|"
    # Romanian
    r"agricultură|creșterea animalelor|"
    r"avicultură|cooperativă agricolă|"
    r"produse agricole|"
    # Hungarian
    r"mezőgazdaság|állattenyésztés|baromfitenyésztés|"
    r"mezőgazdasági szövetkezet|mezőgazdasági termékek|"
    # Greek
    r"γεωργία|κτηνοτροφία|πτηνοτροφία|"
    r"αγροτικός συνεταιρισμός|αγροτικά προϊόντα|"
    # Turkish
    r"tarım|tarımsal işletme|"
    r"hayvancılık|kümes hayvancılığı|"
    r"tarım kooperatifi|tarım ürünleri|"
    # Albanian
    r"bujqësi|blegtori|"
    # Croatian / Serbian / Bosnian
    r"poljoprivreda|stočarstvo|peradarstvo|"
    r"poljoprivredna zadruga|poljoprivredni proizvodi|"
    # Slovenian
    r"kmetijstvo|živinoreja|perutninarstvo|"
    r"kmetijska zadruga|kmetijski proizvodi|"
    # Estonian
    r"põllumajandus|loomakasvatus|linnukasvatus|"
    r"põllumajanduslik ühistu|"
    # Latvian
    r"lauksaimniecība|lopkopība|putnkopība|"
    r"lauksaimniecības kooperatīvs|"
    # Lithuanian
    r"žemės ūkis|gyvulininkystė|paukštininkystė|"
    r"žemės ūkio kooperatyvas|"
    # Finnish
    r"maatalous|karjankasvatus|siipikarjatalous|"
    r"maatalousosuuskunta|maataloustuotteet|"
    # Swedish
    r"jordbruk|boskapsskötsel|fjäderfäskötsel|"
    r"lantbrukskooperativ|jordbruksprodukter|"
    # Norwegian
    r"landbruk|husdyrhold|fjørfehold|"
    r"landbrukssamvirke|"
    # Danish
    r"landbrug|kvægavl|fjerkræavl|"
    r"landbrugskooperativ|landbrugsprodukter|"
    # Icelandic
    r"landbúnaður|búfjárrækt|"
    # Persian
    r"کشاورزی|دامپروری|طیور|"
    r"تعاونی کشاورزی|محصولات کشاورزی|"
    # Arabic
    r"زراعة|تربية الماشية|تربية الدواجن|"
    r"تعاونية زراعية|منتجات زراعية|"
    # Hebrew
    r"חקלאות|גידול בקר|גידול עופות|"
    r"קואופרטיב חקלאי|מוצרים חקלאיים|"
    # Hindi
    r"कृषि|पशुपालन|कुक्कुट पालन|"
    r"कृषि सहकारी|कृषि उत्पाद|"
    # Bengali
    r"কৃষি|গবাদি পশু পালন|হাঁস-মুরগি পালন|"
    # Tamil
    r"விவசாயம்|கால்நடை வளர்ப்பு|"
    # Telugu
    r"వ్యవసాయం|"
    # Marathi
    r"शेती|पशुपालन|"
    # Chinese (Simplified and Traditional)
    r"农业|農業|农业产业|農業產業|"
    r"畜牧业|畜牧業|养殖业|養殖業|家禽养殖|家禽養殖|"
    r"农产品|農產品|农业合作社|農業合作社|"
    # Japanese
    r"農業|畜産業|養鶏|"
    r"農業協同組合|農産物|"
    # Korean
    r"농업|축산업|양계업|"
    r"농업 협동조합|농산물|"
    # Vietnamese
    r"nông nghiệp|chăn nuôi|chăn nuôi gia cầm|"
    r"hợp tác xã nông nghiệp|sản phẩm nông nghiệp|"
    # Thai
    r"เกษตรกรรม|การเลี้ยงสัตว์|การเลี้ยงสัตว์ปีก|"
    r"สหกรณ์การเกษตร|ผลิตภัณฑ์ทางการเกษตร|"
    # Indonesian
    r"pertanian|peternakan|peternakan unggas|"
    r"koperasi pertanian|produk pertanian|"
    # Malay
    r"pertanian|penternakan|penternakan ayam|"
    r"koperasi pertanian|"
    # Filipino (Tagalog)
    r"agrikultura|pag-aalaga ng hayop|"
    # Swahili
    r"kilimo|ufugaji|ushirika wa kilimo|"
    # Catalan
    r"agricultura|ramaderia|cooperativa agrícola|"
    # Welsh
    r"amaethyddiaeth|"
    # Afrikaans
    r"landbou|veeteelt|pluimveebedryf|"
    # Macedonian
    r"земјоделство|сточарство|живинарство|"
    r"земјоделска задруга|земјоделски производи|"
    # Belarusian
    r"сельская гаспадарка|жывёлагадоўля|птушкагадоўля|"
    r"сельскагаспадарчы кааператыў|сельскагаспадарчая прадукцыя|"
    # Azerbaijani
    r"kənd təsərrüfatı|heyvandarlıq|quşçuluq|"
    r"kənd təsərrüfatı kooperativi|kənd təsərrüfatı məhsulları|"
    # Georgian
    r"სოფლის მეურნეობა|მეცხოველეობა|მეფრინველეობა|"
    r"სასოფლო-სამეურნეო კოოპერატივი|სოფლის მეურნეობის პროდუქცია|"
    # Armenian
    r"գյուղատնտեսություն|անասնապահություն|թռչնաբուծություն|"
    r"գյուղատնտեսական կոոպերատիվ|գյուղատնտեսական արտադրանք|"
    # Kazakh
    r"ауыл шаруашылығы|мал шаруашылығы|құс шаруашылығы|"
    r"ауыл шаруашылығы кооперативі|ауыл шаруашылығы өнімдері|"
    # Uzbek
    r"qishloq xo'jaligi|chorvachilik|parrandachilik|"
    r"qishloq xo'jaligi kooperativi|qishloq xo'jaligi mahsulotlari|"
    # Mongolian
    r"хөдөө аж ахуй|мал аж ахуй|шувууны аж ахуй|"
    r"хөдөө аж ахуйн хоршоо|хөдөө аж ахуйн бүтээгдэхүүн|"
    # Khmer
    r"កសិកម្ម|គោក្របី|បសុបក្សី|"
    r"សហករណ៍កសិកម្ម|ផលិតផលកសិកម្ម|"
    # Burmese
    r"လယ်ယာ|မွေးမြူရေး|ကြက်ဥထွက်ရှိ|"
    r"လယ်ယာ စိုက်ပျိုးမှု|"
    # Lao
    r"ກະສິກໍາ|ການລ້ຽງສັດ|ການລ້ຽງສັດປີກ|"
    r"ສະຫະກອນກະສິກໍາ|ຜະລິດຕະພັນກະສິກໍາ|"
    # Nepali
    r"कृषि|पशुपालन|कुक्कुट पालन|"
    r"कृषि सहकारी|कृषि उत्पाद|"
    # Sinhala
    r"කෘෂිකර්මය|පශු සම්පත් පාලනය|කුකුළු පාලනය|"
    r"කෘෂිකාර්මික සමුපකාර|කෘෂිකාර්මික නිෂ්පාදන|"
    # Amharic
    r"ግብርና|እርባታ|"
    r"የግብርና ህብረት ሥራ ማህበር|የግብርና ምርቶች|"
    # Yoruba
    r"àgbẹ̀|ìbísí ẹranko|ìbísí adìẹ|"
    r"àjọṣepọ̀ ìbágbín|"
    # Hausa
    r"noma|kiwo|kiwo na kaji|"
    r"hadin gwiwa na noma|kayan amfanin gona|"
    # Igbo
    r"ọrụ ugbo|ịzụ anụ|ịzụ ọkụkọ|"
    r"òtù ọrụ ugbo|ngwaahịa ugbo|"
    # Zulu
    r"ezolimo|ukufuya izilwane|ukufuya izinkukhu|"
    r"i-cooperative yezolimo|imikhiqizo yezolimo|"
    # Pashto
    r"کرنه|د څارويو روزنه|د چرگو روزنه|"
    r"د کرنې تعاوني|کرنیز محصولات|"
    # Kurdish
    r"çandinî|ajaldarî|mirîşkdarî|"
    r"kooperatîfa çandiniyê|berhemên çandiniyê|"
    # Tajik
    r"кишоварзӣ|чорводорӣ|паррандапарварӣ|"
    r"кооперативи кишоварзӣ|маҳсулоти кишоварзӣ|"
    # Kyrgyz
    r"айыл чарбасы|мал чарба|кушчулук|"
    r"айыл чарба кооперативи|айыл чарба продукциясы|"
    # Maltese
    r"agrikoltura|trobbija tal-bhejjem|trobbija tat-tjur|"
    r"kooperattiva agrikola|prodotti agrikoli|"
    # Luxembourgish
    r"landwirtschaft|déierenzucht|geflüchelzucht|"
    r"landwirtschaftlech genossenschaft|landwirtschaftlech produkter|"
    # Haitian Creole
    r"agrikilti|elvaj bèt|elvaj poul|"
    r"koperativ agrikilti|pwodui agrikòl|"
    # Frisian
    r"lânbou|feehâlderij|plomfeehâlderij|"
    r"lânbouprodukten|"
    # Yiddish
    r"לאַנדווירטשאַפט|בהמות באנוצן|"
    # Faroese
    r"jarðbrúk|búskapur|fjøðurfeavl|"
    # Tatar
    r"авыл хуҗалыгы|терлекчелек|кош үрчетү|"
    # Javanese
    r"pertanian|peternakan|peternakan unggas|"
    r"koperasi pertanian|produk pertanian|"
    # Sundanese
    r"tatanén|peternakan|hasil tatanén|"
    # Cebuano
    r"agrikultura|pagpananom|pag-alima sa hayop|"
    r"kooperatiba sa agrikultura|produkto sa uma"
    r")\b"
)

BEAUTY_RE = re.compile(
    r"(?i)\b("
    # English
    r"beauty salon|beauty products|cosmetics|cosmetic products|"
    r"skincare|skin care|hair salon|"
    r"makeup|fragrance|perfume|"
    r"nail salon|barber shop|spa and wellness|"
    # Spanish
    r"belleza|salón de belleza|productos de belleza|"
    r"cosméticos|productos cosméticos|"
    r"peluquería|barbería|salón de uñas|"
    r"cuidado de la piel|maquillaje|perfumería|"
    # Portuguese
    r"beleza|salão de beleza|"
    r"cosméticos|produtos cosméticos|"
    r"cabeleireiro|barbearia|"
    r"cuidados com a pele|maquiagem|perfumaria|"
    # French
    r"beauté|salon de beauté|cosmétiques|"
    r"produits cosmétiques|salon de coiffure|"
    r"barbier|salon d'esthétique|institut de beauté|"
    r"soins de la peau|parfumerie|"
    # Italian
    r"salone di bellezza|prodotti di bellezza|"
    r"cosmetici|prodotti cosmetici|"
    r"parrucchiere|barbiere|estetista|"
    r"cura della pelle|profumeria|"
    # German
    r"kosmetik|schönheitssalon|friseursalon|"
    r"kosmetikprodukte|kosmetikstudio|"
    r"hautpflege|barbershop|nagelstudio|"
    r"parfümerie|"
    # Dutch
    r"schoonheidssalon|kapsalon|"
    r"cosmeticaproducten|huidverzorging|nagelsalon|"
    # Polish
    r"salon piękności|salon kosmetyczny|"
    r"kosmetyki|produkty kosmetyczne|"
    r"fryzjer|fryzjerstwo|barber shop|"
    r"pielęgnacja skóry|salon paznokci|"
    # Czech
    r"kosmetický salon|kadeřnictví|"
    r"kosmetické výrobky|barber shop|"
    # Slovak
    r"kozmetický salón|kaderníctvo|"
    # Russian
    r"косметика|салон красоты|"
    r"парикмахерская|маникюрный салон|"
    r"уход за кожей|парфюмерия|"
    # Ukrainian
    r"косметика|салон краси|перукарня|"
    # Bulgarian
    r"козметика|фризьорски салон|салон за красота|"
    # Romanian
    r"salon de înfrumusețare|salon de coafură|"
    r"cosmetice|produse cosmetice|frizerie|"
    # Hungarian
    r"szépségszalon|fodrászszalon|"
    r"kozmetikum|borbélyüzlet|körömszalon|"
    # Croatian / Serbian / Bosnian
    r"kozmetički salon|frizerski salon|"
    r"kozmetika|brijačnica|salon za nokte|"
    # Slovenian
    r"kozmetični salon|frizerski salon|"
    # Greek
    r"κομμωτήριο|ινστιτούτο αισθητικής|"
    r"καλλυντικά|μπαρμπέρικο|"
    # Turkish
    r"güzellik salonu|kuaför salonu|"
    r"kozmetik|kozmetik ürünleri|"
    r"berber dükkanı|cilt bakımı|tırnak salonu|"
    # Albanian
    r"sallon bukurie|sallon flokësh|"
    # Estonian
    r"ilusalong|juuksurisalong|kosmeetika|"
    # Latvian
    r"skaistumkopšanas salons|frizētava|kosmētika|"
    # Lithuanian
    r"grožio salonas|kirpykla|kosmetika|"
    # Finnish
    r"kauneushoitola|parturi[- ]kampaamo|kosmetiikka|"
    # Swedish
    r"skönhetssalong|frisersalong|"
    r"kosmetikprodukter|hudvård|"
    # Norwegian
    r"skjønnhetssalong|frisørsalong|kosmetikk|"
    # Danish
    r"skønhedssalon|frisørsalon|kosmetik|"
    # Persian
    r"آرایشگاه|سالن زیبایی|محصولات آرایشی|"
    # Arabic
    r"صالون تجميل|محل حلاقة|"
    r"مستحضرات تجميل|عناية بالبشرة|"
    # Hebrew
    r"מכון יופי|מספרה|מוצרי קוסמטיקה|"
    r"טיפוח עור|מספרת ברבר|"
    # Hindi
    r"ब्यूटी सैलून|सौंदर्य प्रसाधन|"
    r"नाई की दुकान|"
    # Chinese (Simplified and Traditional)
    r"美容|化妆品|化妝品|"
    r"美容院|理发店|理髮店|"
    r"护肤品|護膚品|美甲店|"
    r"香水|"
    # Japanese
    r"美容|化粧品|"
    r"美容院|理髪店|スキンケア|ネイルサロン|"
    # Korean
    r"미용|화장품|"
    r"미용실|이발소|네일 살롱|스킨케어|"
    # Vietnamese
    r"thẩm mỹ viện|tiệm làm tóc|tiệm cắt tóc|"
    r"mỹ phẩm|chăm sóc da|tiệm nail|"
    # Thai
    r"ร้านเสริมสวย|ร้านทำผม|เครื่องสำอาง|"
    r"ร้านบาร์เบอร์|"
    # Indonesian
    r"salon kecantikan|salon rambut|"
    r"produk kosmetik|barbershop|"
    # Malay
    r"salon kecantikan|kedai gunting rambut|kosmetik|"
    # Catalan
    r"saló de bellesa|cosmètics|perruqueria|"
    # Macedonian
    r"салон за убавина|фризерски салон|"
    r"козметика|козметички производи|нега на кожа|"
    r"бербершоп|салон за нокти|"
    # Belarusian
    r"салон прыгажосці|цырульня|"
    r"касметыка|касметычныя сродкі|догляд скуры|"
    r"манікюрны салон|"
    # Azerbaijani
    r"gözəllik salonu|bərbərxana|"
    r"kosmetika|kosmetik məhsullar|dəri qulluğu|"
    r"dırnaq salonu|"
    # Georgian
    r"სილამაზის სალონი|საპარიკმახერო|"
    r"კოსმეტიკა|კოსმეტიკური საშუალებები|"
    r"კანის მოვლა|ფრჩხილების სალონი|"
    # Armenian
    r"գեղեցկության սրահ|վարսահարդարման սրահ|"
    r"կոսմետիկա|կոսմետիկ արտադրանք|"
    r"մաշկի խնամք|"
    # Kazakh
    r"сұлулық салоны|шаштараз|"
    r"косметика|косметикалық өнімдер|"
    r"тері күтімі|"
    # Uzbek
    r"go'zallik saloni|sartaroshxona|"
    r"kosmetika|kosmetik mahsulotlar|"
    r"teri parvarishi|"
    # Mongolian
    r"гоо сайхны салон|үсчин|"
    r"гоо сайхны бүтээгдэхүүн|арьс арчилгаа|"
    # Khmer
    r"ហាងកែសម្ផស្ស|ហាងកាត់សក់|"
    r"គ្រឿងសម្អាង|"
    # Burmese
    r"အလှပြင်ဆိုင်|ဆံပင်ညှပ်ဆိုင်|"
    r"အလှကုန်|"
    # Lao
    r"ຮ້ານເສີມສວຍ|ຮ້ານຕັດຜົມ|"
    r"ເຄື່ອງສຳອາງ|"
    # Nepali
    r"ब्यूटी पार्लर|कपाल काट्ने सलुन|"
    r"सौन्दर्य प्रसाधन|छाला हेरचाह|"
    # Sinhala
    r"රූපලාවණ්‍ය ශාලාව|කොණ්ඩා කපන තැන|"
    r"රූපලාවණ්‍ය නිෂ්පාදන|"
    # Amharic
    r"የውበት ሳሎን|የጸጉር ሳሎን|"
    r"መዋቢያ|"
    # Yoruba
    r"ilé ìṣàra|ilé ìṣẹ́ irun|"
    r"ohun ìṣàra|"
    # Hausa
    r"shagon kyau|shagon aski|"
    r"kayan kwalliya|"
    # Igbo
    r"ụlọ ndozi mma|ụlọ na-ezu isi|"
    r"ngwaahịa mma|"
    # Zulu
    r"isaluni sobuhle|isaluni sezinwele|"
    r"izimonyo|"
    # Pashto
    r"د ښکلا سالون|د ویښتو ډیزاین مرکز|"
    r"کاسمتیک|"
    # Kurdish
    r"salona delaliyê|salona porê|"
    r"kozmetîk|berhemên kozmetîk|"
    # Tajik
    r"салони зебоӣ|салони мӯйсаре|"
    r"маҳсулоти косметикӣ|"
    # Kyrgyz
    r"сулуулук салону|чач тарап|"
    r"косметика|"
    # Maltese
    r"salun tas-sbuħija|salun tax-xagħar|"
    r"kosmetika|prodotti kosmetiċi|"
    # Luxembourgish
    r"schéinheetsalong|coiffeursalong|"
    r"kosmetik|hautfleeg|"
    # Haitian Creole
    r"salon bote|salon kwafi|"
    r"pwodwi kosmetik|swen po|"
    # Frisian
    r"skoanenssalon|kapsalon|"
    r"kosmetyk|"
    # Yiddish
    r"שיינקייט סאלאן|פריזער סאלאן|"
    # Faroese
    r"vakurleikastova|hárklippari|"
    # Tatar
    r"матурлык салоны|чәч тарарга|"
    # Javanese
    r"salon kecantikan|salon rambut|"
    r"kosmetik|"
    # Sundanese
    r"salon kecantikan|"
    # Cebuano
    r"saluna sa kaanyag|saluna sa buhok|"
    r"kosmetiko|pag-atiman sa panit"
    r")\b"
)

CONSTRUCTION_RE = re.compile(
    r"(?i)\b("
    # English
    r"construction company|general contractor|"
    r"building contractor|construction services|"
    r"construction firm|civil engineering|"
    r"home builder|residential construction|"
    r"commercial construction|construction group|"
    # Spanish
    r"empresa de construcción|empresa constructora|"
    r"contratista general|servicios de construcción|"
    r"constructora|ingeniería civil|"
    r"construcción residencial|"
    # Portuguese
    r"construtora|empresa de construção|"
    r"empreiteira|engenharia civil|"
    r"construção residencial|construção comercial|"
    # French
    r"entreprise de construction|entreprise du bâtiment|"
    r"entreprise générale du bâtiment|"
    r"travaux publics|génie civil|"
    r"constructeur de maisons|"
    # Italian
    r"impresa di costruzioni|impresa edile|"
    r"impresa generale di costruzioni|"
    r"ingegneria civile|costruzione residenziale|"
    # German
    r"baufirma|bauunternehmen|bauunternehmer|"
    r"hochbau|tiefbau|generalunternehmer|"
    r"bauträger|hausbau|"
    # Dutch
    r"bouwbedrijf|aannemingsbedrijf|aannemer|"
    r"civiele techniek|woningbouw|"
    # Polish
    r"firma budowlana|generalny wykonawca|"
    r"przedsiębiorstwo budowlane|inżynieria lądowa|"
    r"usługi budowlane|"
    # Czech
    r"stavební společnost|stavební firma|"
    r"generální dodavatel|stavební služby|"
    # Slovak
    r"stavebná spoločnosť|stavebná firma|"
    r"generálny dodávateľ|"
    # Russian
    r"строительная компания|строительная фирма|"
    r"генподрядчик|строительные услуги|"
    r"гражданское строительство|жилищное строительство|"
    # Ukrainian
    r"будівельна компанія|будівельна фірма|"
    r"генпідрядник|"
    # Bulgarian
    r"строителна фирма|строителна компания|"
    # Romanian
    r"firmă de construcții|antreprenor general|"
    r"companie de construcții|"
    # Hungarian
    r"építőipari cég|fővállalkozó|"
    r"építőipari vállalat|"
    # Croatian / Serbian / Bosnian
    r"građevinska kompanija|građevinsko preduzeće|"
    r"građevinska firma|građevinarstvo|"
    # Slovenian
    r"gradbeno podjetje|gradbena dejavnost|"
    # Greek
    r"εταιρεία κατασκευών|κατασκευαστική εταιρεία|"
    r"τεχνική εταιρεία|"
    # Turkish
    r"inşaat şirketi|inşaat firması|"
    r"yapı müteahhidi|inşaat taahhüt|"
    # Albanian
    r"kompani ndërtimi|firmë ndërtimi|"
    # Estonian
    r"ehitusettevõte|peatöövõtja|"
    # Latvian
    r"būvniecības uzņēmums|ģenerāluzņēmējs|"
    # Lithuanian
    r"statybos įmonė|generalinis rangovas|"
    # Finnish
    r"rakennusyhtiö|rakennusliike|pääurakoitsija|"
    # Swedish
    r"byggföretag|byggbolag|generalentreprenör|"
    # Norwegian
    r"byggefirma|byggentreprenør|"
    # Danish
    r"byggefirma|entreprenørvirksomhed|"
    # Icelandic
    r"verktakafyrirtæki|byggingafyrirtæki|"
    # Persian
    r"شرکت ساختمانی|پیمانکار عمومی|"
    # Arabic
    r"شركة البناء|شركة إنشاءات|"
    r"مقاول عام|الهندسة المدنية|"
    # Hebrew
    r"חברת בנייה|קבלן בניין|"
    r"קבלן ראשי|הנדסה אזרחית|"
    # Hindi
    r"निर्माण कंपनी|ठेकेदार|"
    r"भवन निर्माण|सिविल इंजीनियरिंग|"
    # Bengali
    r"নির্মাণ সংস্থা|নির্মাণ কোম্পানি|"
    # Chinese (Simplified and Traditional)
    r"建筑公司|建築公司|建筑工程|建築工程|"
    r"总承包商|總承包商|"
    r"土木工程|施工企业|施工企業|"
    # Japanese
    r"建設会社|建築会社|"
    r"総合建設|土木工事|"
    # Korean
    r"건설회사|건설 회사|"
    r"종합 건설|토목 공사|"
    # Vietnamese
    r"công ty xây dựng|nhà thầu xây dựng|"
    r"kỹ thuật xây dựng|tổng thầu|"
    # Thai
    r"บริษัทรับเหมาก่อสร้าง|"
    r"งานก่อสร้าง|วิศวกรรมโยธา|"
    # Indonesian
    r"perusahaan konstruksi|kontraktor umum|"
    r"jasa konstruksi|teknik sipil|"
    # Malay
    r"syarikat pembinaan|kontraktor pembinaan|"
    # Catalan
    r"empresa de construcció|constructora|"
    # Macedonian
    r"градежна компанија|градежна фирма|"
    r"генерален изведувач|градежни услуги|"
    r"градежно инженерство|"
    # Belarusian
    r"будаўнічая кампанія|будаўнічая фірма|"
    r"генеральны падрадчык|будаўнічыя паслугі|"
    # Azerbaijani
    r"tikinti şirkəti|inşaat şirkəti|"
    r"baş podratçı|tikinti xidmətləri|"
    r"mülki tikinti|ev tikicisi|"
    # Georgian
    r"სამშენებლო კომპანია|მშენებელი ფირმა|"
    r"გენერალური კონტრაქტორი|სამშენებლო მომსახურება|"
    r"სამოქალაქო მშენებლობა|"
    # Armenian
    r"շինարարական ընկերություն|շինարարական ֆիրմա|"
    r"գլխավոր կապալառու|շինարարական ծառայություններ|"
    r"քաղաքացիական շինարարություն|"
    # Kazakh
    r"құрылыс компаниясы|құрылыс фирмасы|"
    r"бас мердігер|құрылыс қызметтері|"
    r"азаматтық құрылыс|"
    # Uzbek
    r"qurilish kompaniyasi|qurilish firmasi|"
    r"bosh pudratchi|qurilish xizmatlari|"
    r"fuqarolik qurilishi|"
    # Mongolian
    r"барилгын компани|барилгын фирм|"
    r"ерөнхий гүйцэтгэгч|барилгын үйлчилгээ|"
    # Khmer
    r"ក្រុមហ៊ុនសំណង់|ក្រុមហ៊ុនកសាង|"
    r"អ្នកម៉ៅការទូទៅ|សេវាសំណង់|"
    # Burmese
    r"ဆောက်လုပ်ရေး ကုမ္ပဏီ|ဆောက်လုပ်ရေး ဖိုရမ်|"
    r"အထွေထွေ ကန်ထရိုက်တာ|ဆောက်လုပ်ရေး ဝန်ဆောင်မှု|"
    # Lao
    r"ບໍລິສັດກໍ່ສ້າງ|ບໍລິສັດການກໍ່ສ້າງ|"
    r"ຜູ້ຮັບເໝົາ ທົ່ວໄປ|"
    # Nepali
    r"निर्माण कम्पनी|निर्माण फर्म|"
    r"सामान्य ठेकेदार|निर्माण सेवा|"
    # Sinhala
    r"ඉදිකිරීම් සමාගම|සිවිල් ඉංජිනේරු|"
    r"ප්‍රධාන කොන්ත්‍රාත්කරු|"
    # Amharic
    r"የግንባታ ኩባንያ|አጠቃላይ ተቋራጭ|"
    r"የግንባታ አገልግሎት|"
    # Yoruba
    r"ilé iṣẹ́ ìkọ̀lé|ilé iṣẹ́ ìmúrasílẹ̀ ilé|"
    r"agbọ́dilé ńlá|"
    # Hausa
    r"kamfanin gini|kwangila ta gaba ɗaya|"
    r"sabis na gini|"
    # Igbo
    r"ụlọ ọrụ owuwu|onye nkwekọrịta izugbe|"
    # Zulu
    r"inkampani yokwakha|umakhi wendlu|"
    r"isigaba sonjiniyela womphakathi|"
    # Pashto
    r"د ودانیزو شرکت|د ودانیزو فرم|"
    r"عمومي قراردادي|د ودانیزو خدمات|"
    # Kurdish
    r"şirketa avahîsaziyê|firma avahîsaziyê|"
    r"sermijar|xizmetên avahîsaziyê|"
    # Tajik
    r"ширкати сохтмонӣ|ширкати бунёд|"
    r"пудратчии умумӣ|хизматрасонии сохтмонӣ|"
    # Kyrgyz
    r"курулуш компаниясы|жалпы подрядчик|"
    r"курулуш кызматтары|"
    # Maltese
    r"kumpanija tal-kostruzzjoni|kuntrattur ġenerali|"
    r"servizzi tal-kostruzzjoni|inġinerija ċivili|"
    # Luxembourgish
    r"baufirma|bauunternehmen|"
    r"generalunternehmer|baudéngschtleeschtungen|"
    # Haitian Creole
    r"konpayi konstriksyon|antreprenè jeneral|"
    r"sèvis konstriksyon|"
    # Frisian
    r"bouwbedriuw|"
    r"generale oannimmer|"
    # Yiddish
    r"בויונג קאמפאני|"
    # Faroese
    r"byggjarí|"
    # Tatar
    r"төзелеш компаниясе|"
    # Javanese
    r"perusahaan konstruksi|kontraktor umum|"
    # Sundanese
    r"perusahaan konstruksi|"
    # Cebuano
    r"kompaniya sa konstruksyon|kontraktor sa konstruksyon|"
    r"serbisyo sa konstruksyon"
    r")\b"
)

CONSULTING_RE = re.compile(
    r"(?i)\b("
    # English
    r"consulting firm|consultancy|management consult|"
    r"strategy consult|business consult|"
    r"advisory services|advisory firm|"
    # Spanish
    r"consultoría|firma de consultoría|"
    r"consultora|asesoría empresarial|"
    r"consultoría de gestión|consultoría estratégica|"
    # Portuguese
    r"consultoria|empresa de consultoria|"
    r"consultoria de gestão|consultoria estratégica|"
    r"assessoria empresarial|"
    # French
    r"cabinet de conseil|société de conseil|"
    r"conseil en management|conseil en stratégie|"
    r"conseil aux entreprises|services de conseil|"
    # Italian
    r"società di consulenza|studio di consulenza|"
    r"consulenza aziendale|consulenza strategica|"
    r"consulenza direzionale|"
    # German
    r"unternehmensberatung|beratungsunternehmen|"
    r"strategieberatung|managementberatung|"
    r"beratungsgesellschaft|"
    # Dutch
    r"adviesbureau|consultancybureau|"
    r"managementadvies|strategieadvies|"
    # Polish
    r"firma konsultingowa|doradztwo|"
    r"firma doradcza|doradztwo strategiczne|"
    r"doradztwo biznesowe|"
    # Czech
    r"poradenská společnost|konzultační firma|"
    r"manažerské poradenství|strategické poradenství|"
    # Slovak
    r"poradenská spoločnosť|konzultačná firma|"
    # Russian
    r"консалтинг|консалтинговая компания|"
    r"управленческий консалтинг|стратегический консалтинг|"
    r"бизнес[- ]консультант|"
    # Ukrainian
    r"консалтингова компанія|"
    # Bulgarian
    r"консултантска фирма|"
    # Romanian
    r"firmă de consultanță|consultanță în management|"
    r"consultanță strategică|"
    # Hungarian
    r"tanácsadó cég|tanácsadó vállalat|"
    r"vezetési tanácsadás|stratégiai tanácsadás|"
    # Croatian / Serbian / Bosnian
    r"konsultantska kuća|konzalting tvrtka|"
    r"poslovno savjetovanje|"
    # Slovenian
    r"svetovalno podjetje|poslovno svetovanje|"
    # Greek
    r"εταιρεία συμβούλων|συμβουλευτική εταιρεία|"
    r"σύμβουλοι διοίκησης|"
    # Turkish
    r"danışmanlık şirketi|yönetim danışmanlığı|"
    r"strateji danışmanlığı|iş danışmanlığı|"
    # Albanian
    r"firmë konsulence|"
    # Estonian
    r"konsultatsioonifirma|nõustamisettevõte|"
    # Latvian
    r"konsultāciju uzņēmums|"
    # Lithuanian
    r"konsultacinė įmonė|valdymo konsultantai|"
    # Finnish
    r"konsulttiyhtiö|johdon konsultointi|"
    # Swedish
    r"konsultföretag|managementkonsult|"
    r"strategikonsult|"
    # Norwegian
    r"konsulentselskap|managementkonsulent|"
    # Danish
    r"konsulentvirksomhed|managementkonsulent|"
    # Persian
    r"شرکت مشاوره|مشاوره مدیریت|"
    # Arabic
    r"شركة استشارات|الاستشارات الإدارية|"
    r"الاستشارات الاستراتيجية|"
    # Hebrew
    r"חברת ייעוץ|ייעוץ ניהולי|ייעוץ אסטרטגי|"
    # Hindi
    r"परामर्श फर्म|प्रबंधन परामर्श|"
    # Bengali
    r"কনসাল্টিং ফার্ম|"
    # Chinese (Simplified and Traditional)
    r"咨询公司|諮詢公司|"
    r"管理咨询|管理諮詢|"
    r"战略咨询|戰略諮詢|"
    # Japanese
    r"コンサルティング会社|"
    r"経営コンサルティング|戦略コンサルティング|"
    # Korean
    r"컨설팅 회사|경영 컨설팅|전략 컨설팅|"
    # Vietnamese
    r"công ty tư vấn|tư vấn quản lý|"
    r"tư vấn chiến lược|"
    # Thai
    r"บริษัทที่ปรึกษา|ที่ปรึกษาการจัดการ|"
    # Indonesian
    r"firma konsultan|konsultan manajemen|"
    r"konsultan strategi|konsultan bisnis|"
    # Malay
    r"firma perundingan|perunding perniagaan|"
    # Catalan
    r"consultoria|empresa de consultoria|"
    # Macedonian
    r"консултантска куќа|консалтинг|"
    r"советодавни услуги|деловно советување|"
    # Belarusian
    r"кансалтынгавая кампанія|кансультацыйная фірма|"
    r"кансультацыйныя паслугі|"
    # Azerbaijani
    r"konsaltinq şirkəti|məsləhət xidmətləri|"
    r"idarəetmə məsləhətçiliyi|biznes məsləhətçiliyi|"
    # Georgian
    r"საკონსულტაციო კომპანია|კონსალტინგი|"
    r"საქმიანი კონსულტაცია|"
    # Armenian
    r"խորհրդատվական ընկերություն|խորհրդատվական ծառայություններ|"
    # Kazakh
    r"кеңес беру компаниясы|кеңес беру қызметтері|"
    r"басқару кеңесі|"
    # Uzbek
    r"konsalting kompaniyasi|maslahat xizmatlari|"
    # Mongolian
    r"зөвлөх компани|зөвлөгөө өгөх үйлчилгээ|"
    # Khmer
    r"ក្រុមហ៊ុនប្រឹក្សា|សេវាប្រឹក្សា|"
    # Burmese
    r"အကြံပေး ကုမ္ပဏီ|"
    # Nepali
    r"परामर्श कम्पनी|व्यवस्थापन परामर्श|"
    # Sinhala
    r"උපදේශන සමාගම|"
    # Amharic
    r"የማማከር ድርጅት|"
    # Hausa
    r"kamfanin tuntuba|"
    # Zulu
    r"inkampani yokucebisana|"
    # Maltese
    r"kumpanija tal-konsulenza|servizzi konsultattivi|"
    # Luxembourgish
    r"berodungsfirma|berodungsdéngschtleeschtungen|"
    # Haitian Creole
    r"konpayi konsiltan|sèvis konsiltatif|"
    # Frisian
    r"adviesburo|"
    # Javanese
    r"perusahaan konsultan|"
    # Cebuano
    r"kompaniya sa konsultasyon"
    r")\b"
)

DEFENSE_RE = re.compile(
    r"(?i)\b("
    # English
    r"defense contractor|defence contractor|"
    r"defense industry|defence industry|"
    r"aerospace and defense|aerospace and defence|"
    r"military equipment|weapons manufacturer|"
    r"military aerospace|defense electronics|defence electronics|"
    # Spanish
    r"industria de defensa|industria armamentística|"
    r"contratista de defensa|fabricante de armamento|"
    r"equipo militar|"
    # Portuguese
    r"indústria de defesa|indústria armamentista|"
    r"contratante de defesa|fabricante de armamento|"
    r"equipamento militar|"
    # French
    r"industrie de défense|industrie de la défense|"
    r"industrie d'armement|fabricant d'armement|"
    r"équipement militaire|électronique de défense|"
    # Italian
    r"industria della difesa|industria degli armamenti|"
    r"appaltatore della difesa|equipaggiamento militare|"
    # German
    r"verteidigungsindustrie|rüstungsindustrie|"
    r"rüstungskonzern|wehrtechnik|"
    r"militärtechnik|militärische ausrüstung|"
    # Dutch
    r"defensie-industrie|wapenindustrie|"
    r"militaire technologie|"
    # Polish
    r"przemysł obronny|przemysł zbrojeniowy|"
    r"sprzęt wojskowy|producent uzbrojenia|"
    # Czech
    r"obranný průmysl|zbrojní průmysl|"
    r"vojenské vybavení|"
    # Slovak
    r"obranný priemysel|zbrojný priemysel|"
    # Russian
    r"оборонная промышленность|оборонный комплекс|"
    r"оборонно-промышленный комплекс|"
    r"военная техника|производитель вооружений|"
    # Ukrainian
    r"оборонна промисловість|оборонно-промисловий комплекс|"
    r"військова техніка|"
    # Bulgarian
    r"отбранителна промишленост|военна индустрия|"
    # Romanian
    r"industrie de apărare|industrie de armament|"
    r"echipament militar|"
    # Hungarian
    r"védelmi ipar|hadiipar|haditechnikai|"
    # Croatian / Serbian / Bosnian
    r"odbrambena industrija|namenska industrija|"
    r"vojna oprema|"
    # Slovenian
    r"obrambna industrija|"
    # Greek
    r"αμυντική βιομηχανία|στρατιωτικός εξοπλισμός|"
    # Turkish
    r"savunma sanayii|savunma sanayi|"
    r"silah üreticisi|askeri teçhizat|"
    r"havacılık ve savunma|"
    # Albanian
    r"industria e mbrojtjes|"
    # Estonian
    r"kaitsetööstus|sõjavarustus|"
    # Latvian
    r"aizsardzības rūpniecība|"
    # Lithuanian
    r"gynybos pramonė|karinė technika|"
    # Finnish
    r"puolustusteollisuus|sotilasteollisuus|"
    r"asevarustelu|sotilaskalusto|"
    # Swedish
    r"försvarsindustri|vapenindustri|"
    r"militär utrustning|"
    # Norwegian
    r"forsvarsindustri|våpenindustri|"
    # Danish
    r"forsvarsindustri|våbenindustri|"
    # Persian
    r"صنایع دفاعی|صنعت تسلیحات|تجهیزات نظامی|"
    # Arabic
    r"الصناعات الدفاعية|الصناعات العسكرية|"
    r"مقاول الدفاع|الفضاء والدفاع|"
    r"معدات عسكرية|"
    # Hebrew
    r"תעשייה ביטחונית|תעשיית הביטחון|"
    r"קבלן ביטחוני|תעשיות נשק|"
    r"מתעשיות אווירונאוטיקה וביטחון|"
    # Hindi
    r"रक्षा उद्योग|सैन्य उपकरण|"
    # Chinese (Simplified and Traditional)
    r"国防工业|國防工業|军工|軍工|"
    r"国防工业|军工产业|軍工產業|"
    r"军事装备|軍事裝備|武器制造|武器製造|"
    r"航空航天与国防|航太與國防|"
    # Japanese
    r"防衛産業|"
    r"航空宇宙・防衛|軍需産業|軍事装備|"
    # Korean
    r"방위산업|방위 산업|"
    r"군수 산업|군사 장비|항공우주 및 방위|"
    # Vietnamese
    r"ngành công nghiệp quốc phòng|"
    r"thiết bị quân sự|nhà thầu quốc phòng|"
    # Thai
    r"อุตสาหกรรมป้องกันประเทศ|อุปกรณ์การทหาร|"
    # Indonesian
    r"industri pertahanan|peralatan militer|"
    # Malay
    r"industri pertahanan|peralatan ketenteraan|"
    # Catalan
    r"indústria de defensa|fabricant d'armament|"
    # Macedonian
    r"одбранбена индустрија|воена опрема|"
    # Belarusian
    r"абарончая прамысловасць|ваенная тэхніка|"
    # Azerbaijani
    r"müdafiə sənayesi|hərbi avadanlıq|"
    # Georgian
    r"თავდაცვის მრეწველობა|სამხედრო აღჭურვილობა|"
    # Armenian
    r"պաշտպանական արդյունաբերություն|ռազմական սարքավորում|"
    # Kazakh
    r"қорғаныс өнеркәсібі|әскери техника|"
    # Uzbek
    r"mudofaa sanoati|harbiy texnika|"
    # Mongolian
    r"батлан хамгаалах үйлдвэрлэл|"
    # Nepali
    r"रक्षा उद्योग|सैन्य उपकरण|"
    # Sinhala
    r"ආරක්ෂක කර්මාන්තය|"
    # Amharic
    r"የመከላከያ ኢንዱስትሪ|"
    # Maltese
    r"industrija tad-difiża|tagħmir militari|"
    # Luxembourgish
    r"verteidigungsindustrie|militärausrüstung|"
    # Haitian Creole
    r"endistri defans|ekipman militè|"
    # Javanese
    r"industri pertahanan|peralatan militer|"
    # Cebuano
    r"industriya sa depensa|kagamitang militar"
    r")\b"
)

EVENT_PLANNING_RE = re.compile(
    r"(?i)\b("
    # English
    r"event planning|event management|"
    r"event production|event services|"
    r"wedding planning|conference planning|"
    r"corporate events|trade show|"
    r"event agency|exhibition organizer|"
    # Spanish
    r"organización de eventos|gestión de eventos|"
    r"agencia de eventos|organización de bodas|"
    r"organización de congresos|eventos corporativos|"
    # Portuguese
    r"organização de eventos|gestão de eventos|"
    r"agência de eventos|organização de casamentos|"
    r"eventos corporativos|"
    # French
    r"organisation d'événements|gestion d'événements|"
    r"agence événementielle|wedding planner|"
    r"organisation de mariages|événements d'entreprise|"
    # Italian
    r"organizzazione di eventi|gestione di eventi|"
    r"agenzia di eventi|wedding planner|"
    r"organizzazione di matrimoni|eventi aziendali|"
    # German
    r"eventmanagement|veranstaltungsorganisation|"
    r"eventagentur|hochzeitsplanung|"
    r"firmenveranstaltung|messeveranstalter|"
    # Dutch
    r"evenementenbureau|evenementenorganisatie|"
    r"trouwplanner|"
    # Polish
    r"organizacja imprez|agencja eventowa|"
    r"planowanie ślubów|eventy firmowe|"
    # Czech
    r"organizace akcí|eventová agentura|"
    r"svatební agentura|"
    # Slovak
    r"organizácia podujatí|eventová agentúra|"
    # Russian
    r"организация мероприятий|агентство мероприятий|"
    r"event[- ]?агентство|организация свадеб|"
    r"корпоративные мероприятия|"
    # Ukrainian
    r"організація заходів|event[- ]агентство|"
    # Bulgarian
    r"организиране на събития|сватбена агенция|"
    # Romanian
    r"organizare de evenimente|agenție de evenimente|"
    r"organizare de nunți|"
    # Hungarian
    r"rendezvényszervezés|esküvőszervező|"
    r"céges rendezvények|"
    # Croatian / Serbian / Bosnian
    r"organizacija događaja|agencija za događaje|"
    r"vjenčanja agencija|"
    # Slovenian
    r"organizacija dogodkov|agencija za dogodke|"
    # Greek
    r"διοργάνωση εκδηλώσεων|γραφείο εκδηλώσεων|"
    r"διοργάνωση γάμων|εταιρικές εκδηλώσεις|"
    # Turkish
    r"etkinlik planlama|etkinlik yönetimi|"
    r"organizasyon şirketi|düğün organizasyonu|"
    r"kurumsal etkinlik|fuar organizatörü|"
    # Albanian
    r"organizim eventesh|"
    # Estonian
    r"sündmuste korraldamine|sündmusagentuur|"
    # Latvian
    r"pasākumu organizēšana|kāzu aģentūra|"
    # Lithuanian
    r"renginių organizavimas|renginių agentūra|"
    # Finnish
    r"tapahtumatoimisto|tapahtumanjärjestäjä|"
    # Swedish
    r"eventbyrå|eventplanering|"
    # Norwegian
    r"arrangementsbyrå|"
    # Danish
    r"eventbureau|begivenhedsplanlægning|"
    # Persian
    r"آژانس برگزاری مراسم|برگزاری رویداد|"
    # Arabic
    r"تنظيم الفعاليات|تنظيم المؤتمرات|"
    r"تنظيم حفلات الزفاف|إدارة الفعاليات|"
    # Hebrew
    r"הפקת אירועים|חברת הפקה|"
    r"תכנון חתונות|אירועים עסקיים|"
    # Hindi
    r"इवेंट प्लानिंग|इवेंट मैनेजमेंट|"
    r"शादी की योजना|"
    # Chinese (Simplified and Traditional)
    r"活动策划|活動策劃|"
    r"活动管理|活動管理|"
    r"婚礼策划|婚禮策劃|"
    r"会议策划|會議策劃|"
    # Japanese
    r"イベント企画|イベント運営|"
    r"ウェディングプランニング|展示会主催|"
    # Korean
    r"이벤트 기획|이벤트 운영|"
    r"웨딩 플래너|기업 행사|"
    # Vietnamese
    r"tổ chức sự kiện|công ty tổ chức sự kiện|"
    r"tổ chức tiệc cưới|sự kiện doanh nghiệp|"
    # Thai
    r"จัดงานอีเวนต์|รับจัดงาน|"
    r"จัดงานแต่งงาน|อีเวนต์องค์กร|"
    # Indonesian
    r"event organizer|organizer pernikahan|"
    r"perusahaan event organizer|"
    # Malay
    r"penganjur acara|wedding planner|"
    # Catalan
    r"organització d'esdeveniments|agència d'esdeveniments|"
    # Macedonian
    r"организација на настани|агенција за настани|"
    r"свадбена агенција|корпоративни настани|"
    # Belarusian
    r"арганізацыя мерапрыемстваў|ягенцыя падзей|"
    # Azerbaijani
    r"tədbir təşkilatı|toy təşkilatı|"
    r"korporativ tədbirlər|"
    # Georgian
    r"ღონისძიებების ორგანიზაცია|სპეციალური ღონისძიებები|"
    r"საქორწინო ორგანიზაცია|"
    # Armenian
    r"միջոցառումների կազմակերպում|հարսանեկան գործակալություն|"
    # Kazakh
    r"іс-шаралар ұйымдастыру|той ұйымдастыру|"
    # Uzbek
    r"tadbirlarni tashkil etish|to'y tashkilotchisi|"
    # Mongolian
    r"арга хэмжээ зохион байгуулах|"
    # Khmer
    r"ការរៀបចំព្រឹត្តិការណ៍|"
    # Burmese
    r"ပွဲစီစဉ်ရေး|ပွဲစီစဉ်ထောက်ပံ့မှု|"
    # Nepali
    r"घटना आयोजना|विवाह योजना|"
    # Sinhala
    r"සිදුවීම් සංවිධානය|"
    # Amharic
    r"የዝግጅት አዘጋጅ|"
    # Hausa
    r"shirya bukukuwa|"
    # Zulu
    r"ukuhlelwa kwemicimbi|"
    # Maltese
    r"organizzazzjoni ta' avvenimenti|"
    r"organizzazzjoni tat-tiġijiet|"
    # Luxembourgish
    r"eventmanagement|veranstaltungsplanung|"
    r"hochzäitsplanung|"
    # Haitian Creole
    r"òganizasyon evènman|òganizasyon maryaj|"
    # Javanese
    r"penyelenggara acara|"
    # Cebuano
    r"organisasyon sa mga panghitabo|paghikay sa kasal"
    r")\b"
)

LOGISTICS_RE = re.compile(
    r"(?i)\b("
    # English
    r"logistics|freight forwarding|freight forwarder|"
    r"shipping and logistics|supply chain|"
    r"customs brokerage|express shipping|"
    r"trucking|cargo services|warehousing|"
    r"third[- ]party logistics|3pl|fourth[- ]party logistics|4pl|"
    # Spanish
    r"logística|transporte de mercancías|"
    r"transitario|cadena de suministro|"
    r"agencia de aduanas|envío urgente|"
    r"servicios de carga|almacenaje|"
    # Portuguese
    r"transporte de cargas|logística|"
    r"despachante aduaneiro|cadeia de suprimentos|"
    r"frete expresso|serviços de carga|armazenagem|"
    # French
    r"logistique|transitaire|"
    r"chaîne d'approvisionnement|chaîne logistique|"
    r"courtage en douane|transport express|"
    r"services de fret|entreposage|"
    # Italian
    r"logistica|spedizioniere|"
    r"catena di approvvigionamento|"
    r"agente doganale|spedizione espresso|"
    r"servizi di carico|stoccaggio|"
    # German
    r"logistikunternehmen|spedition|"
    r"lieferkette|zollabwicklung|"
    r"expressversand|frachtdienstleistungen|lagerhaltung|"
    # Dutch
    r"logistiek|expediteur|toeleveringsketen|"
    r"douane[- ]expediteur|expressbezorging|opslag|"
    # Polish
    r"firma logistyczna|spedycja|"
    r"łańcuch dostaw|agencja celna|"
    r"przesyłki ekspresowe|usługi cargo|magazynowanie|"
    # Czech
    r"logistická společnost|spediční společnost|"
    r"dodavatelský řetězec|celní deklarace|"
    r"expresní zasílání|skladování|"
    # Slovak
    r"logistická spoločnosť|špedičná spoločnosť|"
    r"dodávateľský reťazec|colná deklarácia|"
    # Russian
    r"логистика|логистическая компания|"
    r"экспедиторская компания|"
    r"цепочка поставок|таможенный брокер|"
    r"экспресс[- ]доставка|грузовые услуги|"
    r"складские услуги|"
    # Ukrainian
    r"логістика|логістична компанія|"
    r"ланцюг постачання|митний брокер|"
    # Bulgarian
    r"логистика|логистична компания|"
    r"спедиция|митнически агент|"
    # Romanian
    r"logistică|expediție|"
    r"casă de expediții|broker vamal|"
    r"lanț de aprovizionare|servicii cargo|"
    # Hungarian
    r"logisztika|szállítmányozás|"
    r"ellátási lánc|vámügynök|"
    r"expressz szállítás|raktározás|"
    # Croatian / Serbian / Bosnian
    r"logistika|špedicija|"
    r"lanac snabdijevanja|carinski agent|"
    r"ekspresna dostava|skladištenje|"
    # Slovenian
    r"logistika|špedicija|"
    r"oskrbna veriga|carinski posrednik|"
    # Greek
    r"εφοδιαστική|μεταφορική εταιρεία|"
    r"εκτελωνιστής|αλυσίδα εφοδιασμού|"
    r"ταχυμεταφορές|αποθήκευση εμπορευμάτων|"
    # Turkish
    r"lojistik şirketi|kargo şirketi|"
    r"taşımacılık|nakliye|tedarik zinciri|"
    r"gümrük müşaviri|express kargo|depolama|"
    # Albanian
    r"logjistikë|"
    # Estonian
    r"logistika|ekspedeerimine|tarneahel|"
    r"tolliagentuur|laoteenused|"
    # Latvian
    r"loģistika|ekspedēšana|piegādes ķēde|"
    r"muitas brokeris|noliktavas pakalpojumi|"
    # Lithuanian
    r"logistika|ekspedijavimas|tiekimo grandinė|"
    r"muitinės tarpininkas|sandėliavimas|"
    # Finnish
    r"logistiikka|huolinta|toimitusketju|"
    r"tulliasiointi|pikalähetys|varastointi|"
    # Swedish
    r"logistik|spedition|leverantörskedja|"
    r"tullombud|expressleverans|lagerverksamhet|"
    # Norwegian
    r"logistikk|spedisjon|forsyningskjede|"
    r"tollagent|ekspresslevering|lagring|"
    # Danish
    r"logistik|spedition|forsyningskæde|"
    r"toldekspedition|ekspresforsendelse|lager|"
    # Icelandic
    r"flutningar|vörusending|"
    # Persian
    r"لجستیک|حمل و نقل|زنجیره تامین|"
    r"کارگزار گمرکی|"
    # Arabic
    r"الخدمات اللوجستية|شركة شحن|"
    r"وسيط جمركي|سلسلة التوريد|"
    r"الشحن السريع|التخزين|"
    # Hebrew
    r"לוגיסטיקה|חברת שילוח|שרשרת אספקה|"
    r"סוכן מכס|משלוח אקספרס|אחסנה|"
    # Hindi
    r"रसद|लॉजिस्टिक्स|"
    r"माल अग्रेषण|आपूर्ति श्रृंखला|"
    r"सीमा शुल्क दलाल|"
    # Bengali
    r"লজিস্টিকস|মালামাল পরিবহন|সরবরাহ শৃঙ্খল|"
    # Tamil
    r"தளவாட சேவை|"
    # Chinese (Simplified and Traditional)
    r"物流公司|物流服务|物流服務|货运代理|貨運代理|"
    r"供应链|供應鏈|"
    r"报关行|報關行|"
    r"快递服务|快遞服務|仓储|倉儲|"
    # Japanese
    r"物流|物流会社|物流サービス|"
    r"フォワーダー|サプライチェーン|"
    r"通関業|宅配便|倉庫業|"
    # Korean
    r"물류 회사|물류 서비스|"
    r"공급망 관리|관세사|"
    r"특송 서비스|창고 서비스|"
    # Vietnamese
    r"công ty hậu cần|công ty logistics|"
    r"giao nhận hàng hóa|chuỗi cung ứng|"
    r"dịch vụ hải quan|chuyển phát nhanh|kho bãi|"
    # Thai
    r"บริษัทโลจิสติกส์|การขนส่ง|"
    r"ห่วงโซ่อุปทาน|ตัวแทนพิธีการศุลกากร|"
    r"การขนส่งด่วน|คลังสินค้า|"
    # Indonesian
    r"perusahaan logistik|jasa pengiriman|"
    r"rantai pasokan|broker bea cukai|"
    r"pengiriman ekspres|pergudangan|"
    # Malay
    r"syarikat logistik|rangkaian bekalan|"
    r"penghantaran ekspres|pergudangan|"
    # Filipino (Tagalog)
    r"kumpanya ng lohistika|kumpanya ng logistics|"
    # Catalan
    r"logística|cadena de subministrament|"
    # Galician
    r"loxística|"
    # Welsh
    r"logisteg|"
    # Swahili
    r"shughuli za usafirishaji|usafirishaji wa mizigo|"
    # Afrikaans
    r"logistiek|spedisie|"
    # Macedonian
    r"логистика|логистичка компанија|"
    r"шпедиција|синџир на снабдување|"
    r"царинска агенција|експресна достава|"
    # Belarusian
    r"лагістыка|лагістычная кампанія|"
    r"экспедытар|ланцуг паставак|"
    r"мытны агент|экспрэс дастаўка|"
    # Azerbaijani
    r"logistika|logistik şirkəti|"
    r"ekspeditor|təchizat zənciri|"
    r"gömrük brokeri|ekspres çatdırılma|"
    # Georgian
    r"ლოჯისტიკა|ლოჯისტიკის კომპანია|"
    r"საექსპედიტორო|მომარაგების ჯაჭვი|"
    r"საბაჟო ბროკერი|ექსპრეს მიწოდება|"
    # Armenian
    r"լոգիստիկա|լոգիստիկ ընկերություն|"
    r"փոխադրման գործակալություն|մատակարարման շղթա|"
    r"մաքսային գործակալ|սուրհանդակային ծառայություն|"
    # Kazakh
    r"логистика|логистикалық компания|"
    r"экспедитор|жеткізу тізбегі|"
    r"кеден брокері|жедел жеткізу|"
    # Uzbek
    r"logistika|logistika kompaniyasi|"
    r"ekspeditor|ta'minot zanjiri|"
    r"bojxona brokeri|tezkor yetkazib berish|"
    # Mongolian
    r"логистик|логистикийн компани|"
    r"экспедитор|нийлүүлэлтийн сүлжээ|"
    r"гаалийн брокер|шуурхай хүргэлт|"
    # Khmer
    r"ភស្តុភារ|ក្រុមហ៊ុនភស្តុភារ|"
    r"អ្នកដឹកជញ្ជូន|ខ្សែសង្វាក់ផ្គត់ផ្គង់|"
    r"ឈ្មួញគយ|ការដឹកបញ្ជូនរហ័ស|"
    # Burmese
    r"ထောက်ပံ့ပို့ဆောင်ရေး|ထောက်ပံ့ပို့ဆောင်ရေး ကုမ္ပဏီ|"
    r"ထောက်ပံ့ရေး ကွင်းဆက်|အမြန်ပို့ဆောင်မှု|"
    # Lao
    r"ການຂົນສົ່ງ|ບໍລິສັດການຂົນສົ່ງ|"
    r"ໂສ້ການສະໜອງ|ນາຍໜ້າພາສີ|"
    # Nepali
    r"रसद कम्पनी|लजिस्टिक्स कम्पनी|"
    r"आपूर्ति श्रृंखला|भन्सार दलाल|"
    # Sinhala
    r"ලොජිස්ටික් සමාගම|සැපයුම් දාම|"
    r"රේගු තැරැව්කරු|"
    # Amharic
    r"ሎጂስቲክስ ኩባንያ|የአቅርቦት ሰንሰለት|"
    r"የጉምሩክ ወኪል|"
    # Yoruba
    r"ilé iṣẹ́ ìpèsè ọjà|ìpèsè ètò ìṣòwò|"
    # Hausa
    r"kamfanin tafiyar da kayayyaki|"
    r"jerin samar da kayayyaki|"
    # Igbo
    r"ụlọ ọrụ ozugbo|olu ụlọ ọrụ na-eweta ngwaahịa|"
    # Zulu
    r"inkampani ye-logistics|"
    r"isigaba sokuhlinzeka|umphathi we-customs|"
    # Pashto
    r"لوژستیکي شرکت|د عرضې سلسله|"
    r"د گمرک دلال|"
    # Kurdish
    r"şirketa logistîkê|zincîra dabînkirinê|"
    r"navenda gumrikê|"
    # Tajik
    r"ширкати логистикӣ|занҷираи таъминот|"
    r"брокери гумрукӣ|"
    # Kyrgyz
    r"логистикалык компания|жеткирүү чынжыры|"
    r"бажы брокери|"
    # Maltese
    r"kumpanija tal-loġistika|"
    r"katina ta' provvista|sensar tad-dwana|"
    r"konsenja express|"
    # Luxembourgish
    r"logistik|logistikfirma|"
    r"liwwerkette|zollagent|"
    r"express liwwerung|"
    # Haitian Creole
    r"konpayi lojistik|chèn distribisyon|"
    r"kourtye ladwan|livrezon ekspres|"
    # Frisian
    r"logistyk|logistyk bedriuw|"
    r"oanleveringsketen|"
    # Yiddish
    r"לאָגיסטיק|"
    # Faroese
    r"flutningsfelag|"
    # Tatar
    r"логистика|логистика компаниясе|"
    # Javanese
    r"perusahaan logistik|rantai pasokan|"
    r"layanan logistik|"
    # Sundanese
    r"logistik|"
    # Cebuano
    r"kompaniya sa logistics|kadena sa suplay|"
    r"broker sa customs"
    r")\b"
)

MSSP_RE = re.compile(
    r"(?i)\b("
    # English
    r"mssp\b|managed security services|"
    r"managed security service provider|"
    r"managed detection and response|mdr\b|"
    r"managed cybersecurity|security operations center|security operations centre|soc\b|"
    # Spanish
    r"servicios de seguridad gestionados|"
    r"servicios de ciberseguridad gestionados|"
    r"centro de operaciones de seguridad|"
    # Portuguese
    r"serviços de segurança gerenciados|"
    r"serviços de cibersegurança gerenciados|"
    r"centro de operações de segurança|"
    # French
    r"services de sécurité gérés|"
    r"services de cybersécurité gérés|"
    r"centre des opérations de sécurité|"
    # Italian
    r"servizi di sicurezza gestiti|"
    r"servizi di cybersecurity gestiti|"
    r"centro operativo di sicurezza|"
    # German
    r"managed security|cyber security dienst|"
    r"verwaltete sicherheitsdienste|"
    r"managed[- ]security[- ]anbieter|"
    # Dutch
    r"beheerde beveiligingsdiensten|"
    # Polish
    r"zarządzane usługi bezpieczeństwa|"
    r"zarządzane usługi cyberbezpieczeństwa|"
    # Czech
    r"řízené bezpečnostní služby|"
    # Russian
    r"управляемые услуги безопасности|"
    r"управляемая кибербезопасность|"
    # Turkish
    r"yönetilen güvenlik hizmetleri|"
    r"siber güvenlik operasyon merkezi|"
    # Greek
    r"διαχειριζόμενες υπηρεσίες ασφαλείας|"
    # Romanian
    r"servicii de securitate gestionate|"
    # Arabic
    r"خدمات الأمن المدارة|مركز عمليات الأمن|"
    # Hebrew
    r"שירותי אבטחה מנוהלים|"
    # Persian
    r"خدمات امنیتی مدیریت شده|"
    # Chinese (Simplified and Traditional)
    r"托管安全服务|託管安全服務|"
    r"安全运营中心|安全運營中心|"
    # Japanese
    r"マネージドセキュリティサービス|"
    r"セキュリティオペレーションセンター|"
    # Korean
    r"관리형 보안 서비스|보안 관제 센터|"
    # Macedonian
    r"управувани безбедносни услуги|"
    # Azerbaijani
    r"idarə olunan təhlükəsizlik xidmətləri|"
    # Georgian
    r"მართული უსაფრთხოების სერვისები|"
    # Armenian
    r"կառավարվող անվտանգության ծառայություններ|"
    # Kazakh
    r"басқарылатын қауіпсіздік қызметтері|"
    # Uzbek
    r"boshqariladigan xavfsizlik xizmatlari|"
    # Maltese
    r"servizzi tas-sigurtà ġestiti|"
    # Luxembourgish
    r"verwaltete sécherheetsdéngschtleeschtungen|"
    # Haitian Creole
    r"sèvis sekirite jere|"
    # Javanese
    r"layanan keamanan terkelola|"
    # Cebuano
    r"managed security services"
    r")\b"
)

NEWS_RE = re.compile(
    r"(?i)\b("
    # English
    r"news organization|newspaper|news network|news publisher|"
    r"newsroom|news media|breaking news|"
    r"news outlet|news website|"
    r"news agency|press agency|news portal|"
    # Spanish
    r"diario|periódico|noticias|"
    r"agencia de noticias|portal de noticias|"
    r"medio de comunicación|sala de redacción|"
    # Portuguese
    r"jornal|jornal diário|"
    r"agência de notícias|portal de notícias|"
    r"redação|veículo de comunicação|"
    # French
    r"journal|quotidien|hebdomadaire|"
    r"agence de presse|portail d'actualités|"
    r"rédaction|salle de rédaction|"
    # Italian
    r"giornale|quotidiano|"
    r"agenzia di stampa|portale di notizie|"
    r"redazione|testata giornalistica|"
    # German
    r"zeitung|nachrichtenmedium|tageszeitung|"
    r"nachrichtenagentur|presseagentur|"
    r"nachrichtenportal|redaktion|"
    # Dutch
    r"krant|nieuwsmedium|nieuwsagentschap|"
    r"persbureau|nieuwsportaal|"
    # Polish
    r"gazeta|portal informacyjny|dziennik|"
    r"agencja prasowa|agencja informacyjna|redakcja|"
    # Czech
    r"noviny|deník|tisková agentura|"
    r"zpravodajský portál|redakce|"
    # Slovak
    r"noviny|denník|tlačová agentúra|"
    r"spravodajský portál|"
    # Russian
    r"редакция|информационное агентство|"
    r"газета|новостной портал|"
    r"новостное издание|информационный портал|"
    # Ukrainian
    r"редакція|інформаційне агентство|"
    r"газета|новинний портал|"
    # Bulgarian
    r"вестник|информационна агенция|"
    r"новинарски сайт|редакция|"
    # Romanian
    r"ziar|cotidian|agenție de presă|"
    r"portal de știri|redacție|"
    # Hungarian
    r"újság|napilap|hírügynökség|"
    r"hírportál|szerkesztőség|"
    # Croatian / Serbian / Bosnian
    r"novine|dnevni list|novinska agencija|"
    r"informativni portal|redakcija|"
    # Slovenian
    r"časopis|tiskovna agencija|novinski portal|"
    # Greek
    r"εφημερίδα|πρακτορείο ειδήσεων|"
    r"ειδησεογραφικός ιστότοπος|"
    # Turkish
    r"gazete|haber ajansı|"
    r"haber portalı|haber sitesi|yayın kuruluşu|"
    # Albanian
    r"gazetë|agjenci lajmesh|portal lajmesh|"
    # Estonian
    r"ajaleht|uudisteagentuur|uudisteportaal|"
    # Latvian
    r"avīze|ziņu aģentūra|ziņu portāls|"
    # Lithuanian
    r"laikraštis|naujienų agentūra|naujienų portalas|"
    # Finnish
    r"sanomalehti|uutistoimisto|uutissivusto|"
    # Swedish
    r"tidning|nyhetsbyrå|nyhetstjänst|nyhetssajt|"
    # Norwegian
    r"avis|nyhetsbyrå|nyhetsportal|"
    # Danish
    r"avis|nyhedsbureau|nyhedsportal|"
    # Icelandic
    r"dagblað|fréttastofa|fréttavefur|"
    # Persian
    r"روزنامه|خبرگزاری|پایگاه خبری|"
    # Arabic
    r"صحيفة|جريدة|وكالة أنباء|"
    r"موقع إخباري|تحرير|"
    # Hebrew
    r"עיתון|סוכנות ידיעות|אתר חדשות|מערכת|"
    # Hindi
    r"समाचार पत्र|समाचार एजेंसी|समाचार वेबसाइट|"
    # Bengali
    r"সংবাদপত্র|সংবাদ সংস্থা|"
    # Tamil
    r"செய்தித்தாள்|செய்தி நிறுவனம்|"
    # Chinese (Simplified and Traditional)
    r"新闻|新聞|新闻网站|新聞網站|报纸|報紙|"
    r"通讯社|通訊社|新闻机构|新聞機構|"
    r"新闻门户|新聞入口|"
    # Japanese
    r"新聞社|通信社|報道機関|ニュースサイト|"
    # Korean
    r"신문사|통신사|언론사|뉴스 사이트|"
    # Vietnamese
    r"báo|nhật báo|hãng thông tấn|"
    r"trang tin tức|tòa soạn|"
    # Thai
    r"หนังสือพิมพ์|สำนักข่าว|เว็บไซต์ข่าว|"
    # Indonesian
    r"surat kabar|kantor berita|portal berita|"
    # Malay
    r"akhbar|agensi berita|portal berita|"
    # Filipino (Tagalog)
    r"pahayagan|ahensiya ng balita|"
    # Swahili
    r"gazeti|shirika la habari|"
    # Catalan
    r"diari|agència de notícies|portal de notícies|"
    # Macedonian
    r"весник|новинска агенција|"
    r"новинска редакција|информативен портал|"
    # Belarusian
    r"газета|інфармацыйнае агенцтва|"
    r"навіннае выданне|рэдакцыя|"
    # Azerbaijani
    r"qəzet|xəbər agentliyi|"
    r"xəbər portalı|redaksiya|nəşriyyat|"
    # Georgian
    r"გაზეთი|საინფორმაციო სააგენტო|"
    r"საინფორმაციო პორტალი|რედაქცია|"
    # Armenian
    r"թերթ|լրատվական գործակալություն|"
    r"լրատվական կայք|խմբագրություն|"
    # Kazakh
    r"газет|ақпарат агенттігі|"
    r"жаңалықтар порталы|редакция|"
    # Uzbek
    r"gazeta|axborot agentligi|"
    r"yangiliklar portali|tahririyat|"
    # Mongolian
    r"сонин|мэдээллийн агентлаг|"
    r"мэдээний портал|редакц|"
    # Khmer
    r"កាសែត|ទីភ្នាក់ងារព័ត៌មាន|"
    r"គេហទំព័រព័ត៌មាន|ផ្នែកកែសម្រួល|"
    # Burmese
    r"သတင်းစာ|သတင်းအေဂျင်စီ|"
    r"သတင်းဝက်ဘ်ဆိုက်|အယ်ဒီတာအဖွဲ့|"
    # Lao
    r"ໜັງສືພິມ|ອົງການຂ່າວ|"
    r"ເວັບໄຊຂ່າວ|ກອງບັນນາທິການ|"
    # Nepali
    r"समाचारपत्र|समाचार एजेन्सी|"
    r"समाचार पोर्टल|सम्पादन कक्ष|"
    # Sinhala
    r"පුවත්පත|ප්‍රවෘත්ති ආයතනය|"
    r"ප්‍රවෘත්ති වෙබ් අඩවිය|"
    # Amharic
    r"ጋዜጣ|የዜና ኤጀንሲ|"
    r"የዜና ድረ ገጽ|"
    # Yoruba
    r"ìwé ìròyìn|ilé iṣẹ́ ìròyìn|"
    r"orí àyẹ́wò|"
    # Hausa
    r"jarida|kamfanin watsa labarai|"
    r"shafin yanar gizo na labarai|"
    # Igbo
    r"akwụkwọ akụkọ|ụlọ ọrụ akụkọ|"
    # Zulu
    r"iphephandaba|inhlangano yezindaba|"
    r"isizinda sezindaba|"
    # Pashto
    r"ورځپاڼه|د خبرونو اداره|"
    r"د خبرونو ویب پاڼه|"
    # Kurdish
    r"rojname|ajansa nûçeyan|"
    r"malpera nûçeyan|sernivîsar|"
    # Tajik
    r"рӯзнома|агентии хабарӣ|"
    r"портали хабарӣ|"
    # Kyrgyz
    r"гезит|маалымат агенттиги|"
    r"жаңылык порталы|"
    # Maltese
    r"gazzetta|aġenzija tal-aħbarijiet|"
    r"sit tal-aħbarijiet|redazzjoni|"
    # Luxembourgish
    r"zeitung|noriichtenagentur|"
    r"noriichtenportal|redaktioun|"
    # Haitian Creole
    r"jounal|ajans laprès|"
    r"sit aktyalite|redaksyon|"
    # Frisian
    r"krante|nijsburo|"
    r"nijsside|redaksje|"
    # Yiddish
    r"צייטונג|נייעס אגענטור|"
    # Faroese
    r"blað|tíðindastova|"
    # Tatar
    r"газета|хәбәр агентлыгы|"
    # Javanese
    r"koran|kantor berita|"
    r"portal berita|"
    # Sundanese
    r"koran|kantor berita|"
    # Cebuano
    r"mantalaan|ahensya sa balita|"
    r"website sa balita"
    r")\b"
)

NONPROFIT_RE = re.compile(
    r"(?i)\b("
    # English
    r"nonprofit|non[- ]profit|not[- ]for[- ]profit|"
    r"charity|charitable organization|charitable foundation|"
    r"501\(c\)\(3\)|registered charity|"
    r"humanitarian organization|relief organization|"
    r"foundation for|community foundation|"
    # Spanish
    r"organización sin fines de lucro|"
    r"organización sin ánimo de lucro|"
    r"fundación benéfica|asociación benéfica|"
    r"organización benéfica|ong\b|"
    # Portuguese
    r"organização sem fins lucrativos|"
    r"entidade sem fins lucrativos|"
    r"fundação beneficente|ong\b|"
    # French
    r"organisation à but non lucratif|"
    r"association caritative|fondation caritative|"
    r"organisation caritative|ong\b|"
    # Italian
    r"organizzazione senza scopo di lucro|"
    r"organizzazione no profit|"
    r"fondazione benefica|onlus|ong\b|"
    # German
    r"gemeinnützige|nichtregierungsorganisation|"
    r"wohltätigkeitsorganisation|gemeinnützige stiftung|"
    r"hilfsorganisation|"
    # Dutch
    r"non[- ]profitorganisatie|liefdadigheidsinstelling|"
    r"goede doelen|"
    # Polish
    r"organizacja non[- ]profit|"
    r"organizacja charytatywna|fundacja charytatywna|"
    r"organizacja pożytku publicznego|"
    # Czech
    r"nezisková organizace|charitativní organizace|"
    # Slovak
    r"nezisková organizácia|charitatívna organizácia|"
    # Russian
    r"некоммерческая организация|"
    r"благотворительная организация|"
    r"благотворительный фонд|"
    # Ukrainian
    r"некомерційна організація|"
    r"благодійна організація|благодійний фонд|"
    # Bulgarian
    r"нестопанска организация|благотворителна организация|"
    # Romanian
    r"organizație non[- ]profit|"
    r"organizație caritabilă|fundație caritabilă|"
    # Hungarian
    r"nonprofit szervezet|jótékonysági szervezet|"
    r"alapítvány|"
    # Croatian / Serbian / Bosnian
    r"neprofitna organizacija|"
    r"humanitarna organizacija|dobrotvorna organizacija|"
    # Slovenian
    r"neprofitna organizacija|dobrodelna organizacija|"
    # Albanian
    r"organizatë jofitimprurëse|organizatë bamirëse|"
    # Greek
    r"μη κερδοσκοπικός οργανισμός|"
    r"φιλανθρωπική οργάνωση|"
    # Turkish
    r"kâr amacı gütmeyen|"
    r"hayır kurumu|yardım kuruluşu|vakıf|"
    # Estonian
    r"mittetulundusühing|heategevusorganisatsioon|"
    # Latvian
    r"bezpeļņas organizācija|labdarības organizācija|"
    # Lithuanian
    r"ne pelno siekianti organizacija|labdaros organizacija|"
    # Finnish
    r"voittoa tavoittelematon|hyväntekeväisyysjärjestö|"
    # Swedish
    r"ideell organisation|välgörenhetsorganisation|"
    # Norwegian
    r"ideell organisasjon|veldedighetsorganisasjon|"
    # Danish
    r"nonprofit organisation|velgørenhedsorganisation|"
    # Icelandic
    r"sjálfseignarstofnun|"
    # Persian
    r"سازمان غیرانتفاعی|سازمان خیریه|"
    # Arabic
    r"منظمة غير ربحية|منظمة خيرية|مؤسسة خيرية|"
    # Hebrew
    r"עמותה|ארגון ללא מטרות רווח|ארגון צדקה|"
    # Hindi
    r"गैर लाभकारी संगठन|धर्मार्थ संगठन|"
    # Bengali
    r"অলাভজনক সংস্থা|দাতব্য সংস্থা|"
    # Chinese (Simplified and Traditional)
    r"非营利组织|非營利組織|"
    r"慈善机构|慈善機構|"
    r"公益组织|公益組織|基金会|基金會|"
    # Japanese
    r"非営利団体|慈善団体|公益財団|"
    # Korean
    r"비영리 단체|비영리 기구|자선 단체|재단|"
    # Vietnamese
    r"tổ chức phi lợi nhuận|tổ chức từ thiện|"
    # Thai
    r"องค์กรไม่แสวงหาผลกำไร|องค์กรการกุศล|"
    # Indonesian
    r"organisasi nirlaba|yayasan amal|"
    # Malay
    r"organisasi bukan keuntungan|pertubuhan amal|"
    # Filipino (Tagalog)
    r"non[- ]profit na samahan|"
    # Swahili
    r"shirika lisilo la kibiashara|shirika la hisani|"
    # Catalan
    r"organització sense ànim de lucre|fundació benèfica|"
    # Welsh
    r"sefydliad dielw|"
    # Afrikaans
    r"nie[- ]winsgewende organisasie|"
    # Macedonian
    r"непрофитна организација|добротворна организација|"
    r"добротворна фондација|"
    # Belarusian
    r"некамерцыйная арганізацыя|дабрачынная арганізацыя|"
    # Azerbaijani
    r"qeyri-kommersiya təşkilatı|xeyriyyə təşkilatı|"
    # Georgian
    r"არასამეწარმეო ორგანიზაცია|საქველმოქმედო ორგანიზაცია|"
    # Armenian
    r"ոչ առևտրային կազմակերպություն|բարեգործական կազմակերպություն|"
    # Kazakh
    r"коммерциялық емес ұйым|қайырымдылық ұйымы|"
    # Uzbek
    r"notijorat tashkilot|xayriya tashkiloti|"
    # Mongolian
    r"ашгийн бус байгууллага|буяны байгууллага|"
    # Khmer
    r"អង្គការមិនរកប្រាក់ចំណេញ|អង្គការសប្បុរសធម៌|"
    # Burmese
    r"အကျိုးအမြတ် မဖြစ်စေသော အဖွဲ့အစည်း|ပရဟိတအဖွဲ့|"
    # Lao
    r"ອົງການບໍ່ສະແຫວງຫາກໍາໄລ|"
    # Nepali
    r"गैर नाफामुखी संस्था|दातव्य संस्था|"
    # Sinhala
    r"ලාභ නොලබන සංවිධානය|පුණ්‍යාධාර සංවිධානය|"
    # Amharic
    r"ለትርፍ ያልተቋቋመ ድርጅት|የበጎ አድራጎት ድርጅት|"
    # Yoruba
    r"àjọ aláìní èrè|"
    # Hausa
    r"ƙungiyar ba ta neman riba|kungiyar agaji|"
    # Zulu
    r"inhlangano engenanzuzo|inhlangano yesisa|"
    # Pashto
    r"غیر انتفاعي سازمان|د خیریې سازمان|"
    # Kurdish
    r"rêxistina ne-qarûker|rêxistina xêrxwaz|"
    # Tajik
    r"созмони ғайритиҷоратӣ|созмони хайриявӣ|"
    # Maltese
    r"organizzazzjoni mhux għall-profitt|organizzazzjoni tal-karità|"
    # Luxembourgish
    r"gemeinnütz organisatioun|wuelfäerts organisatioun|"
    # Haitian Creole
    r"òganizasyon san bi likratif|òganizasyon charitab|"
    # Frisian
    r"non-profitorganisaasje|"
    # Javanese
    r"organisasi nirlaba|yayasan amal|"
    # Cebuano
    r"non[- ]profit nga organisasyon|charitable nga organisasyon"
    r")\b"
)

PHOTOGRAPHY_RE = re.compile(
    r"(?i)\b("
    # English
    r"photography studio|photo studio|"
    r"professional photographer|wedding photographer|"
    r"commercial photography|stock photography|"
    r"portrait photography|event photography|"
    # Spanish
    r"estudio fotográfico|fotógrafo profesional|"
    r"fotógrafo de bodas|fotografía comercial|"
    # Portuguese
    r"estúdio fotográfico|fotógrafo profissional|"
    r"fotógrafo de casamento|fotografia comercial|"
    # French
    r"studio photo|studio de photographie|"
    r"photographe professionnel|photographe de mariage|"
    r"photographie commerciale|"
    # Italian
    r"studio fotografico|fotografo professionista|"
    r"fotografo di matrimoni|fotografia commerciale|"
    # German
    r"fotostudio|berufsfotograf|"
    r"hochzeitsfotograf|werbefotograf|"
    # Dutch
    r"fotostudio|professionele fotograaf|trouwfotograaf|"
    # Polish
    r"studio fotograficzne|fotograf ślubny|"
    r"profesjonalny fotograf|"
    # Czech
    r"fotografické studio|svatební fotograf|"
    # Slovak
    r"fotografické štúdio|svadobný fotograf|"
    # Russian
    r"фотостудия|профессиональный фотограф|"
    r"свадебный фотограф|"
    # Ukrainian
    r"фотостудія|весільний фотограф|"
    # Romanian
    r"studio foto|fotograf profesionist|fotograf de nuntă|"
    # Hungarian
    r"fotóstúdió|esküvői fotós|"
    # Greek
    r"φωτογραφικό στούντιο|επαγγελματίας φωτογράφος|"
    # Turkish
    r"fotoğraf stüdyosu|profesyonel fotoğrafçı|"
    r"düğün fotoğrafçısı|"
    # Croatian / Serbian / Bosnian
    r"fotografski studio|svadbeni fotograf|"
    # Slovenian
    r"fotografski studio|poročni fotograf|"
    # Estonian
    r"fotostuudio|pulmafotograaf|"
    # Latvian
    r"fotogrāfijas studija|kāzu fotogrāfs|"
    # Lithuanian
    r"fotostudija|vestuvių fotografas|"
    # Finnish
    r"valokuvastudio|hääkuvaaja|"
    # Swedish
    r"fotostudio|bröllopsfotograf|"
    # Norwegian
    r"fotostudio|bryllupsfotograf|"
    # Danish
    r"fotostudie|bryllupsfotograf|"
    # Icelandic
    r"ljósmyndastofa|"
    # Persian
    r"استودیو عکاسی|عکاس حرفه‌ای|"
    # Arabic
    r"استوديو تصوير|مصور محترف|مصور حفلات الزفاف|"
    # Hebrew
    r"סטודיו לצילום|צלם מקצועי|צלם חתונות|"
    # Hindi
    r"फोटो स्टूडियो|शादी का फोटोग्राफर|"
    # Chinese (Simplified and Traditional)
    r"摄影工作室|攝影工作室|"
    r"婚纱摄影|婚紗攝影|商业摄影|商業攝影|"
    # Japanese
    r"写真スタジオ|フォトスタジオ|"
    r"ウェディングフォト|プロカメラマン|"
    # Korean
    r"사진 스튜디오|웨딩 사진|전문 사진작가|"
    # Vietnamese
    r"studio chụp ảnh|nhiếp ảnh chuyên nghiệp|"
    r"chụp ảnh cưới|"
    # Thai
    r"สตูดิโอถ่ายภาพ|ช่างภาพมืออาชีพ|"
    # Indonesian
    r"studio foto|fotografer profesional|fotografer pernikahan|"
    # Malay
    r"studio foto|jurugambar profesional|"
    # Catalan
    r"estudi fotogràfic|fotògraf de noces|"
    # Macedonian
    r"фотографско студио|свадбен фотограф|"
    r"професионален фотограф|"
    # Belarusian
    r"фотастудыя|вясельны фатограф|"
    r"прафесійны фатограф|"
    # Azerbaijani
    r"foto studiyası|toy fotoqrafı|"
    r"peşəkar fotoqraf|"
    # Georgian
    r"ფოტო სტუდია|საქორწილო ფოტოგრაფი|"
    r"პროფესიონალი ფოტოგრაფი|"
    # Armenian
    r"լուսանկարչական ստուդիա|հարսանեկան լուսանկարիչ|"
    r"մասնագիտական լուսանկարիչ|"
    # Kazakh
    r"фото студия|той фотографы|"
    r"кәсіби фотограф|"
    # Uzbek
    r"foto studiya|to'y fotografi|"
    r"professional fotograf|"
    # Mongolian
    r"фото студи|хуримын зурагчин|"
    # Khmer
    r"ស្ទូឌីយោថត|ជាងថតអាពាហ៍ពិពាហ៍|"
    # Burmese
    r"ဓာတ်ပုံ စတူဒီယို|မင်္ဂလာဆောင်ဓာတ်ပုံဆရာ|"
    # Nepali
    r"फोटो स्टुडियो|विवाह फोटोग्राफर|"
    # Sinhala
    r"ඡායාරූප ස්ටුඩියෝව|විවාහ ඡායාරූප ශිල්පියා|"
    # Amharic
    r"የፎቶ ስቱዲዮ|የሰርግ ፎቶግራፈር|"
    # Yoruba
    r"ilé iṣẹ́ àwòrán|"
    # Hausa
    r"shagon hoto|mai daukar hoto na bikin aure|"
    # Zulu
    r"isitudiyo sezithombe|"
    # Maltese
    r"stuldju tar-ritratti|fotografu tat-tiġijiet|"
    # Luxembourgish
    r"fotostudio|hochzäitsfotograf|"
    # Haitian Creole
    r"estidyo foto|fotograf maryaj|"
    # Frisian
    r"fotostudio|brulloftsfotograaf|"
    # Javanese
    r"studio foto|fotografer pernikahan|"
    # Cebuano
    r"estudyo sa litrato|magkukuha sa litrato sa kasal"
    r")\b"
)

PHYSICAL_SECURITY_RE = re.compile(
    r"(?i)\b("
    # English
    r"security guards?|alarm system|alarm monitoring|"
    r"surveillance system|access control system|"
    r"cctv|security cameras?|"
    r"physical security|guard services|"
    # Spanish
    r"empresa de seguridad|seguridad privada|"
    r"sistema de alarma|circuito cerrado|"
    r"control de accesos|videovigilancia|"
    r"servicio de vigilancia|"
    # Portuguese
    r"empresa de segurança|segurança privada|"
    r"sistema de alarme|controle de acesso|"
    r"videomonitoramento|videovigilância|"
    # French
    r"sécurité privée|société de gardiennage|"
    r"système d'alarme|contrôle d'accès|"
    r"vidéosurveillance|télésurveillance|"
    # Italian
    r"vigilanza privata|sistema di allarme|"
    r"videosorveglianza|controllo accessi|"
    # German
    r"sicherheitsdienst|wachdienst|"
    r"alarmanlage|alarmsystem|"
    r"videoüberwachung|zutrittskontrolle|"
    # Dutch
    r"beveiligingsbedrijf|alarmsysteem|"
    r"camerabewaking|toegangscontrole|"
    # Polish
    r"firma ochroniarska|system alarmowy|"
    r"monitoring wizyjny|kontrola dostępu|"
    # Czech
    r"bezpečnostní agentura|zabezpečovací systém|"
    r"kamerový systém|"
    # Slovak
    r"bezpečnostná agentúra|"
    r"kamerový systém|"
    # Russian
    r"охранная компания|охранное предприятие|"
    r"охранное агентство|охранные услуги|"
    r"система сигнализации|видеонаблюдение|"
    r"система контроля доступа|"
    # Ukrainian
    r"охоронна компанія|охоронні послуги|"
    r"відеоспостереження|"
    # Bulgarian
    r"охранителна фирма|видеонаблюдение|"
    # Romanian
    r"firmă de pază|sistem de alarmă|"
    r"supraveghere video|control acces|"
    # Hungarian
    r"vagyonőrző cég|biztonsági szolgálat|"
    r"riasztórendszer|videómegfigyelés|"
    # Croatian / Serbian / Bosnian
    r"agencija za zaštitu|alarmni sistem|"
    r"video nadzor|kontrola pristupa|"
    # Slovenian
    r"varnostna služba|alarmni sistem|"
    r"video nadzor|"
    # Greek
    r"εταιρεία ασφαλείας|σύστημα συναγερμού|"
    r"βιντεοπαρακολούθηση|έλεγχος πρόσβασης|"
    # Turkish
    r"güvenlik şirketi|alarm sistemi|"
    r"kamera sistemi|geçiş kontrol|"
    # Albanian
    r"kompani sigurie|sistem alarmi|"
    # Estonian
    r"turvateenused|valvesüsteem|videovalve|"
    # Latvian
    r"apsardzes uzņēmums|signalizācijas sistēma|"
    r"videonovērošana|"
    # Lithuanian
    r"apsaugos įmonė|signalizacijos sistema|"
    r"vaizdo stebėjimas|"
    # Finnish
    r"vartiointiliike|hälytysjärjestelmä|"
    r"valvontakamerat|kulunvalvonta|"
    # Swedish
    r"säkerhetsbolag|larmsystem|"
    r"kameraövervakning|passersystem|"
    # Norwegian
    r"vakttjeneste|alarmsystem|"
    r"kameraovervåking|"
    # Danish
    r"vagtselskab|alarmsystem|"
    r"videoovervågning|"
    # Persian
    r"شرکت امنیتی|سیستم هشدار|"
    r"دوربین مداربسته|کنترل دسترسی|"
    # Arabic
    r"شركة أمن|نظام إنذار|"
    r"كاميرات مراقبة|التحكم بالدخول|"
    # Hebrew
    r"חברת אבטחה|מערכת אזעקה|"
    r"מצלמות אבטחה|בקרת כניסה|"
    # Hindi
    r"सुरक्षा कंपनी|सीसीटीवी|"
    r"अलार्म सिस्टम|"
    # Chinese (Simplified and Traditional)
    r"安保公司|保安公司|"
    r"报警系统|報警系統|监控系统|監控系統|"
    r"门禁系统|門禁系統|视频监控|視頻監控|"
    # Japanese
    r"警備会社|警備保障|"
    r"防犯カメラ|入退室管理|"
    # Korean
    r"보안 회사|경비 회사|"
    r"경보 시스템|cctv 카메라|출입 통제|"
    # Vietnamese
    r"công ty bảo vệ|hệ thống báo động|"
    r"giám sát camera|kiểm soát ra vào|"
    # Thai
    r"บริษัทรักษาความปลอดภัย|กล้องวงจรปิด|"
    # Indonesian
    r"perusahaan keamanan|sistem alarm|kamera pengawas|"
    # Malay
    r"syarikat keselamatan|sistem penggera|"
    r"kamera pengawasan|"
    # Macedonian
    r"безбедносна компанија|алармен систем|"
    r"видео надзор|контрола на пристап|"
    # Belarusian
    r"ахоўная кампанія|сістэма сігналізацыі|"
    r"відэаназіранне|"
    # Azerbaijani
    r"təhlükəsizlik şirkəti|həyəcan sistemi|"
    r"video nəzarət|giriş nəzarəti|"
    # Georgian
    r"უსაფრთხოების კომპანია|სიგნალიზაციის სისტემა|"
    r"ვიდეო ზედამხედველობა|"
    # Armenian
    r"անվտանգության ընկերություն|ազդանշանային համակարգ|"
    r"վիդեո հսկողություն|"
    # Kazakh
    r"күзет компаниясы|дабыл жүйесі|"
    r"бейне бақылау|"
    # Uzbek
    r"qo'riqlash kompaniyasi|signalizatsiya tizimi|"
    r"video nazorat|"
    # Mongolian
    r"хамгаалалтын компани|дохиоллын систем|"
    # Khmer
    r"ក្រុមហ៊ុនសន្តិសុខ|ប្រព័ន្ធជូនដំណឹង|"
    # Burmese
    r"လုံခြုံရေး ကုမ္ပဏီ|အချက်ပေးစနစ်|"
    # Nepali
    r"सुरक्षा कम्पनी|अलार्म प्रणाली|"
    # Sinhala
    r"ආරක්ෂක සමාගම|"
    # Amharic
    r"የጥበቃ ኩባንያ|"
    # Hausa
    r"kamfanin tsaro|tsarin ƙararrawa|"
    # Zulu
    r"inkampani yezokuvikela|uhlelo lwe-alamu|"
    # Maltese
    r"kumpanija tas-sigurtà|sistema tal-allarm|"
    r"sorveljanza bil-vidjo|"
    # Luxembourgish
    r"sécherheetsfirma|alarmsystem|"
    r"videoiwwerwaachung|"
    # Haitian Creole
    r"konpayi sekirite|sistèm alam|"
    # Javanese
    r"perusahaan keamanan|sistem alarm|"
    # Cebuano
    r"kompaniya sa seguridad|sistema sa alarma"
    r")\b"
)

PRINT_RE = re.compile(
    r"(?i)\b("
    # English
    r"printing company|printing services|"
    r"commercial printing|print shop|print provider|"
    r"offset printing|digital printing|large format printing|"
    # Spanish
    r"imprenta|impresor|servicios de impresión|"
    r"impresión digital|impresión offset|"
    # Portuguese
    r"impressão|gráfica|serviços gráficos|"
    r"impressão digital|impressão offset|"
    # French
    r"imprimerie|atelier d'impression|"
    r"impression numérique|impression offset|"
    # Italian
    r"tipografia|stamperia|servizi di stampa|"
    r"stampa digitale|stampa offset|"
    # German
    r"druckerei|druckdienstleister|"
    r"digitaldruck|offsetdruck|"
    # Dutch
    r"drukkerij|drukservice|"
    r"digitaal drukwerk|"
    # Polish
    r"drukarnia|usługi drukarskie|"
    r"druk cyfrowy|druk offsetowy|"
    # Czech
    r"tiskárna|tiskové služby|"
    r"digitální tisk|ofsetový tisk|"
    # Slovak
    r"tlačiareň|tlačové služby|digitálna tlač|"
    # Russian
    r"типография|полиграфия|"
    r"полиграфические услуги|цифровая печать|"
    # Ukrainian
    r"типографія|поліграфія|"
    # Bulgarian
    r"печатница|печатни услуги|"
    # Romanian
    r"tipografie|servicii de tipărire|"
    # Hungarian
    r"nyomda|nyomdai szolgáltatások|"
    # Croatian / Serbian / Bosnian
    r"tiskara|štamparija|tiskarske usluge|"
    # Slovenian
    r"tiskarna|tiskarske storitve|"
    # Greek
    r"τυπογραφείο|υπηρεσίες εκτύπωσης|"
    # Turkish
    r"matbaa|baskı hizmetleri|dijital baskı|"
    # Albanian
    r"shtypshkronjë|"
    # Estonian
    r"trükikoda|trükiteenused|"
    # Latvian
    r"tipogrāfija|drukāšanas pakalpojumi|"
    # Lithuanian
    r"spaustuvė|spausdinimo paslaugos|"
    # Finnish
    r"painotalo|painotuote|painopalvelu|"
    # Swedish
    r"tryckeri|trycksaker|"
    # Norwegian
    r"trykkeri|trykksaker|"
    # Danish
    r"trykkeri|trykkeritjenester|"
    # Icelandic
    r"prentsmiðja|"
    # Persian
    r"چاپخانه|خدمات چاپ|"
    # Arabic
    r"مطبعة|خدمات الطباعة|طباعة رقمية|"
    # Hebrew
    r"בית דפוס|שירותי דפוס|"
    # Hindi
    r"प्रिंटिंग कंपनी|प्रिंटिंग सेवाएं|"
    # Chinese (Simplified and Traditional)
    r"印刷公司|印刷厂|印刷廠|"
    r"印刷服务|印刷服務|"
    r"数码印刷|數位印刷|"
    # Japanese
    r"印刷会社|印刷サービス|"
    # Korean
    r"인쇄소|인쇄 회사|인쇄 서비스|"
    # Vietnamese
    r"công ty in ấn|dịch vụ in ấn|"
    # Thai
    r"โรงพิมพ์|บริการพิมพ์|"
    # Indonesian
    r"perusahaan percetakan|layanan cetak|"
    # Malay
    r"syarikat percetakan|"
    # Catalan
    r"impremta|"
    # Macedonian
    r"печатница|печатарски услуги|"
    # Belarusian
    r"друкарня|"
    # Azerbaijani
    r"mətbəə|çap xidmətləri|"
    # Georgian
    r"სტამბა|ბეჭდვითი მომსახურება|"
    # Armenian
    r"տպարան|տպագրական ծառայություններ|"
    # Kazakh
    r"баспахана|баспа қызметтері|"
    # Uzbek
    r"bosmaxona|chop xizmatlari|"
    # Mongolian
    r"хэвлэх үйлдвэр|"
    # Khmer
    r"រោងពុម្ព|"
    # Burmese
    r"ပုံနှိပ်တိုက်|"
    # Lao
    r"ໂຮງພິມ|"
    # Nepali
    r"प्रिन्टिङ कम्पनी|छापाखाना|"
    # Sinhala
    r"මුද්‍රණ ආයතනය|"
    # Amharic
    r"የህትመት ኩባንያ|"
    # Yoruba
    r"ilé ìtẹ̀wé|"
    # Hausa
    r"kamfanin bugawa|"
    # Zulu
    r"inkampani yokuphrinta|"
    # Maltese
    r"stamperija|servizzi tal-istampar|"
    # Luxembourgish
    r"dréckerei|"
    # Haitian Creole
    r"konpayi enprime|"
    # Frisian
    r"drukkerij|"
    # Javanese
    r"perusahaan percetakan|"
    # Cebuano
    r"kompaniya sa pag-imprenta"
    r")\b"
)

PUBLISHING_RE = re.compile(
    r"(?i)\b("
    # English
    r"publishing house|book publisher|"
    r"academic publisher|magazine publisher|"
    r"editorial group|publishing group|"
    r"scholarly publisher|trade publisher|"
    # Spanish
    r"editorial|casa editorial|grupo editorial|"
    r"editorial académica|editorial universitaria|"
    # Portuguese
    r"editora|grupo editorial|editora acadêmica|"
    # French
    r"maison d'édition|groupe d'édition|"
    r"éditions universitaires|"
    # Italian
    r"casa editrice|gruppo editoriale|"
    r"editore accademico|"
    # German
    r"verlag|verlagshaus|verlagsgruppe|"
    r"wissenschaftsverlag|"
    # Dutch
    r"uitgeverij|uitgevershuis|"
    # Polish
    r"wydawnictwo|grupa wydawnicza|wydawnictwo naukowe|"
    # Czech
    r"nakladatelství|vydavatelství|"
    # Slovak
    r"vydavateľstvo|"
    # Russian
    r"издательство|издательский дом|"
    r"издательская группа|научное издательство|"
    # Ukrainian
    r"видавництво|видавничий дім|"
    # Bulgarian
    r"издателство|издателска къща|"
    # Romanian
    r"editură|grup editorial|"
    # Hungarian
    r"kiadó|könyvkiadó|kiadóház|"
    # Croatian / Serbian / Bosnian
    r"izdavačka kuća|izdavačka grupa|"
    # Slovenian
    r"založba|knjižna založba|"
    # Greek
    r"εκδοτικός οίκος|εκδοτικός όμιλος|"
    # Turkish
    r"yayınevi|yayın grubu|akademik yayıncı|"
    # Albanian
    r"shtëpi botuese|"
    # Estonian
    r"kirjastus|kirjastusgrupp|"
    # Latvian
    r"izdevniecība|"
    # Lithuanian
    r"leidykla|leidybinė grupė|"
    # Finnish
    r"kustantamo|kustannusyhtiö|"
    # Swedish
    r"förlag|bokförlag|förlagsgrupp|"
    # Norwegian
    r"forlag|bokforlag|"
    # Danish
    r"forlag|forlagsgruppe|"
    # Icelandic
    r"bókaforlag|"
    # Persian
    r"انتشارات|ناشر کتاب|"
    # Arabic
    r"دار النشر|دار نشر|"
    # Hebrew
    r"הוצאה לאור|הוצאת ספרים|"
    # Hindi
    r"प्रकाशन गृह|पुस्तक प्रकाशक|"
    # Bengali
    r"প্রকাশনা সংস্থা|বই প্রকাশক|"
    # Chinese (Simplified and Traditional)
    r"出版社|出版公司|出版集团|出版集團|"
    r"图书出版|圖書出版|"
    # Japanese
    r"出版社|出版グループ|学術出版|"
    # Korean
    r"출판사|출판 그룹|"
    # Vietnamese
    r"nhà xuất bản|nhà phát hành sách|"
    # Thai
    r"สำนักพิมพ์|"
    # Indonesian
    r"penerbit|perusahaan penerbit|"
    # Malay
    r"penerbit|syarikat penerbitan|"
    # Catalan
    r"editorial|grup editorial|"
    # Macedonian
    r"издавачка куќа|издавачка група|"
    # Belarusian
    r"выдавецтва|выдавецкі дом|"
    # Azerbaijani
    r"nəşriyyat|nəşriyyat evi|"
    # Georgian
    r"გამომცემლობა|საგამომცემლო ჯგუფი|"
    # Armenian
    r"հրատարակչություն|"
    # Kazakh
    r"баспа|баспа үйі|баспа тобы|"
    # Uzbek
    r"nashriyot|nashriyot uyi|"
    # Mongolian
    r"хэвлэлийн газар|"
    # Khmer
    r"ការបោះពុម្ពផ្សាយ|"
    # Burmese
    r"ထုတ်ဝေရေး|စာအုပ်ထုတ်ဝေသူ|"
    # Lao
    r"ບໍລິສັດການພິມ|"
    # Nepali
    r"प्रकाशन गृह|पुस्तक प्रकाशक|"
    # Sinhala
    r"ප්‍රකාශන ආයතනය|පොත් ප්‍රකාශක|"
    # Amharic
    r"የህትመት ድርጅት|"
    # Yoruba
    r"ilé ìtẹ̀wé|"
    # Hausa
    r"gidan bugawa|mawallafi|"
    # Zulu
    r"ishicilelo|inkampani yokushicilela|"
    # Maltese
    r"dar tal-pubblikazzjoni|pubblikatur tal-kotba|"
    # Luxembourgish
    r"verlag|verlagshaus|"
    # Haitian Creole
    r"konpayi pibliye|edisyon liv|"
    # Frisian
    r"útjouwerij|"
    # Javanese
    r"penerbit|penerbit buku|"
    # Cebuano
    r"magmamantala|kompaniya sa pagmantala"
    r")\b"
)

RELIGION_RE = re.compile(
    r"(?i)\b("
    # English
    r"church|cathedral|parish|diocese|"
    r"mosque|synagogue|temple|monastery|"
    r"religious organization|religious community|"
    r"faith community|ministries|"
    r"archdiocese|congregation|seminary|"
    # Spanish
    r"iglesia|parroquia|catedral|diócesis|"
    r"mezquita|sinagoga|templo|monasterio|"
    r"comunidad religiosa|"
    # Portuguese
    r"igreja|paróquia|catedral|diocese|"
    r"mesquita|sinagoga|templo|mosteiro|"
    r"comunidade religiosa|"
    # French
    r"église|paroisse|cathédrale|diocèse|"
    r"mosquée|synagogue|temple|monastère|"
    r"communauté religieuse|"
    # Italian
    r"chiesa|parrocchia|cattedrale|diocesi|"
    r"moschea|sinagoga|tempio|monastero|"
    r"comunità religiosa|"
    # German
    r"kirche|gemeinde|kathedrale|"
    r"erzbistum|bistum|moschee|synagoge|"
    r"tempel|kloster|"
    # Dutch
    r"kerk|parochie|kathedraal|bisdom|"
    r"moskee|synagoge|klooster|"
    # Polish
    r"kościół|parafia|katedra|diecezja|"
    r"meczet|synagoga|świątynia|klasztor|"
    # Czech
    r"kostel|farnost|katedrála|diecéze|"
    r"mešita|synagoga|chrám|klášter|"
    # Slovak
    r"kostol|farnosť|katedrála|diecéza|"
    r"mešita|synagóga|chrám|kláštor|"
    # Russian
    r"церковь|приход|собор|епархия|"
    r"мечеть|синагога|храм|монастырь|"
    r"религиозная организация|"
    # Ukrainian
    r"церква|парафія|собор|"
    r"мечеть|синагога|храм|"
    # Bulgarian
    r"църква|енория|катедрала|"
    r"джамия|синагога|храм|манастир|"
    # Romanian
    r"biserică|parohie|catedrală|dioceză|"
    r"moschee|sinagogă|templu|mănăstire|"
    # Hungarian
    r"templom|plébánia|székesegyház|egyházmegye|"
    r"mecset|zsinagóga|kolostor|"
    # Croatian / Serbian / Bosnian
    r"crkva|župa|katedrala|"
    r"džamija|sinagoga|hram|samostan|"
    # Slovenian
    r"cerkev|župnija|katedrala|"
    r"mošeja|sinagoga|tempelj|samostan|"
    # Greek
    r"εκκλησία|ενορία|καθεδρικός|"
    r"μητρόπολη|συναγωγή|τέμενος|μοναστήρι|"
    # Turkish
    r"camii|cami|kilise|katedral|"
    r"sinagog|tapınak|manastır|"
    # Albanian
    r"kishë|xhami|sinagogë|manastir|"
    # Estonian
    r"kirik|kogudus|katedraal|"
    r"mošee|sünagoog|klooster|"
    # Latvian
    r"baznīca|katedrāle|mošeja|sinagoga|klosteris|"
    # Lithuanian
    r"bažnyčia|katedra|parapija|"
    r"mečetė|sinagoga|vienuolynas|"
    # Finnish
    r"kirkko|seurakunta|katedraali|"
    r"moskeija|synagoga|temppeli|luostari|"
    # Swedish
    r"kyrka|församling|katedral|stift|"
    r"moské|synagoga|tempel|kloster|"
    # Norwegian
    r"kirke|menighet|katedral|bispedømme|"
    r"moské|synagoge|tempel|kloster|"
    # Danish
    r"kirke|sogn|katedral|stift|"
    r"moské|synagoge|tempel|kloster|"
    # Icelandic
    r"kirkja|söfnuður|dómkirkja|"
    # Persian
    r"کلیسا|مسجد|کنیسه|معبد|صومعه|"
    # Urdu
    r"مسجد|کلیسا|"
    # Arabic
    r"مسجد|كنيسة|كاتدرائية|"
    r"كنيس|معبد|دير|أبرشية|"
    # Hebrew
    r"בית כנסת|כנסייה|מנזר|מסגד|"
    # Hindi
    r"मंदिर|चर्च|मस्जिद|आराधनालय|गुरुद्वारा|"
    # Bengali
    r"মন্দির|গির্জা|মসজিদ|"
    # Tamil
    r"கோவில்|தேவாலயம்|பள்ளிவாசல்|"
    # Punjabi
    r"ਗੁਰਦੁਆਰਾ|ਮੰਦਰ|"
    # Thai
    r"วัด|โบสถ์|มัสยิด|"
    # Chinese (Simplified and Traditional)
    r"教会|教會|清真寺|"
    r"教堂|大教堂|寺庙|寺廟|"
    r"犹太教堂|猶太教堂|修道院|"
    # Japanese
    r"教会|寺院|神社|"
    r"大聖堂|モスク|シナゴーグ|修道院|"
    # Korean
    r"교회|성당|사찰|"
    r"대성당|교구|모스크|회당|수도원|"
    # Vietnamese
    r"nhà thờ|nhà thờ chính tòa|giáo xứ|"
    r"đền|chùa|nhà thờ hồi giáo|"
    # Indonesian
    r"gereja|katedral|paroki|"
    r"masjid|sinagoga|kuil|biara|"
    # Malay
    r"gereja|masjid|kuil|biara|"
    # Filipino (Tagalog)
    r"simbahan|katedral|parokya|"
    r"moske|templo|"
    # Swahili
    r"kanisa|msikiti|hekalu|"
    # Catalan
    r"església|parròquia|catedral|diòcesi|"
    r"mesquita|sinagoga|temple|monestir|"
    # Macedonian
    r"црква|џамија|манастир|катедрала|"
    r"парохија|епархија|синагога|"
    r"верска заедница|верска организација|"
    # Belarusian
    r"царква|касцёл|мячэць|"
    r"сінагога|манастыр|катэдральны сабор|"
    r"парафія|рэлігійная супольнасць|"
    # Azerbaijani
    r"məscid|kilsə|kafedral|"
    r"sinaqoq|monastır|məbəd|"
    r"dini icma|dini təşkilat|"
    # Georgian
    r"ეკლესია|საკათედრო ტაძარი|მეჩეთი|მონასტერი|"
    r"სინაგოგა|სამრევლო|ეპარქია|"
    r"რელიგიური თემი|"
    # Armenian
    r"եկեղեցի|մայր տաճար|մզկիթ|վանք|"
    r"սինագոգ|ծխական|թեմ|"
    r"կրոնական համայնք|կրոնական կազմակերպություն|"
    # Kazakh
    r"мешіт|шіркеу|монастырь|"
    r"синагога|храм|"
    r"діни қауымдастық|діни ұйым|"
    # Uzbek
    r"masjid|cherkov|monastir|"
    r"sinagoga|ma'bad|"
    r"diniy jamoa|diniy tashkilot|"
    # Mongolian
    r"сүм|хийд|сүм хийд|"
    r"сүмын дуган|шашны байгууллага|"
    r"шашны нийгэмлэг|"
    # Khmer
    r"វត្ត|ព្រះវិហារ|ម៉ូស្គេ|"
    r"ស៊ីណាហ្គោក|សេនេទ|"
    r"សហគមន៍សាសនា|អង្គការសាសនា|"
    # Burmese
    r"ဘုရားကျောင်း|ပုထိုး|ဗလီ|"
    r"ဂျူးဘုန်းကြီးကျောင်း|ဘုန်းကြီးကျောင်း|"
    r"ဘာသာရေး အသိုက်အဝန်း|ဘာသာရေးအဖွဲ့အစည်း|"
    # Lao
    r"ວັດ|ໂບດ|ມັສຍິດ|"
    r"ສາລາ|ອົງການສາສະໜາ|"
    # Nepali
    r"मन्दिर|गिरजाघर|मस्जिद|"
    r"सिनागग|बौद्ध विहार|गुम्बा|"
    r"धार्मिक समुदाय|धार्मिक संस्था|"
    # Sinhala
    r"පන්සල|පල්ලිය|මුස්ලිම් පල්ලිය|"
    r"සිනගෝගය|විහාරය|"
    r"ආගමික ප්‍රජාව|ආගමික සංවිධානය|"
    # Amharic
    r"ቤተ ክርስቲያን|መስጊድ|"
    r"የአይሁድ ቤተ ጸሎት|ገዳም|"
    r"ሃይማኖታዊ ማህበረሰብ|ሃይማኖታዊ ድርጅት|"
    # Yoruba
    r"ṣọ́ọ̀ṣì|mọ́sálásí|"
    r"sinagọ́gì|ilé ìjọ́sìn|"
    r"àdúgbò ẹ̀sìn|ìjọ ẹ̀sìn|"
    # Hausa
    r"masallaci|coci|"
    r"majami'a|gidan addu'a|"
    r"al'umma ta addini|kungiyar addini|"
    # Igbo
    r"ụka|ụlọ alụsị|"
    r"ụlọ ekpere|"
    r"òtù okpukpe|nzukọ okpukpe|"
    # Zulu
    r"isonto|isiqephu|"
    r"i-mosque|i-synagogue|i-temple|"
    r"umphakathi wenkolo|inhlangano yenkolo|"
    # Pashto
    r"جومات|کلیسا|"
    r"کنیسه|معبد|خانقاه|"
    r"دیني ټولنه|دیني سازمان|"
    # Kurdish
    r"mizgeft|kenîse|"
    r"kinîşt|perestgeh|keşîşxane|"
    r"civaka olî|saziya olî|"
    # Tajik
    r"масҷид|калисо|"
    r"куништ|маъбад|"
    r"ҷамъияти динӣ|созмони динӣ|"
    # Kyrgyz
    r"мечит|чиркөө|"
    r"синагога|храм|монастырь|"
    r"диний жамаат|диний уюм|"
    # Maltese
    r"knisja|moskea|sinagoga|kunvent|"
    r"katidral|parroċċa|djoċesi|"
    r"komunità reliġjuża|organizzazzjoni reliġjuża|"
    # Luxembourgish
    r"kierch|moschee|sinagog|kapell|"
    r"kathedral|por|bistum|klouschter|"
    r"reliéis gemeinschaft|reliéis organisatioun|"
    # Haitian Creole
    r"legliz|moske|"
    r"sinagòg|tanp|monastè|"
    r"kominote relijye|òganizasyon relijye|"
    # Frisian
    r"tsjerke|moskee|"
    r"synagoge|timpel|kleaster|"
    r"religieuze mienskip|"
    # Yiddish
    r"שיל|בית מדרש|"
    r"קלויסטער|קאָנגרעגאַציע|"
    r"רעליגיעזע קהילה|"
    # Faroese
    r"kirkja|moskea|"
    r"klostur|kirkjuligt felag|"
    # Tatar
    r"мәчет|чиркәү|"
    r"синагога|монастырь|"
    r"дини җәмгыять|дини оешма|"
    # Javanese
    r"gereja|masjid|pura|"
    r"sinagoga|wihara|biara|"
    r"komunitas keagamaan|"
    # Sundanese
    r"masjid|gareja|"
    r"pura|wihara|biara|"
    # Cebuano
    r"simbahan|moske|"
    r"sinagoga|templo|monasteryo|"
    r"komunidad nga relihiyoso"
    r")\b"
)

SCIENCE_RE = re.compile(
    r"(?i)\b("
    # English
    r"research institute|research laboratory|research center|research centre|"
    r"scientific research|laboratory of\b|"
    r"national laboratory|observatory|"
    r"academy of sciences|center of excellence|"
    # Spanish
    r"instituto de investigación|laboratorio nacional|"
    r"investigación científica|centro de investigación|"
    r"academia de ciencias|observatorio astronómico|"
    # Portuguese
    r"instituto de pesquisa|laboratório nacional|"
    r"pesquisa científica|centro de pesquisa|"
    r"academia de ciências|observatório astronômico|"
    # French
    r"institut de recherche|laboratoire national|"
    r"recherche scientifique|centre de recherche|"
    r"académie des sciences|observatoire astronomique|"
    # Italian
    r"istituto di ricerca|laboratorio nazionale|"
    r"ricerca scientifica|centro di ricerca|"
    r"accademia delle scienze|osservatorio astronomico|"
    # German
    r"forschungsinstitut|forschungslabor|"
    r"wissenschaftliche forschung|forschungszentrum|"
    r"akademie der wissenschaften|sternwarte|"
    # Dutch
    r"onderzoeksinstituut|onderzoekslaboratorium|"
    r"wetenschappelijk onderzoek|"
    # Polish
    r"instytut badawczy|laboratorium naukowe|"
    r"badania naukowe|centrum badawcze|"
    r"akademia nauk|obserwatorium astronomiczne|"
    # Czech
    r"výzkumný ústav|vědecká laboratoř|"
    r"vědecký výzkum|akademie věd|hvězdárna|"
    # Slovak
    r"výskumný ústav|vedecké laboratórium|"
    r"akadémia vied|hvezdáreň|"
    # Russian
    r"научно-исследовательский институт|"
    r"научный институт|научно-исследовательская лаборатория|"
    r"научное исследование|академия наук|"
    r"астрономическая обсерватория|"
    # Ukrainian
    r"науково-дослідний інститут|"
    r"наукова лабораторія|академія наук|"
    # Bulgarian
    r"научно-изследователски институт|"
    r"научна лаборатория|академия на науките|"
    # Romanian
    r"institut de cercetare|laborator de cercetare|"
    r"cercetare științifică|academia de științe|"
    # Hungarian
    r"kutatóintézet|kutatólaboratórium|"
    r"tudományos kutatás|tudományos akadémia|"
    # Croatian / Serbian / Bosnian
    r"istraživački institut|istraživački centar|"
    r"akademija nauka|znanstveno istraživanje|"
    # Slovenian
    r"raziskovalni inštitut|raziskovalni center|"
    r"znanstvenoraziskovalni|akademija znanosti|"
    # Greek
    r"ερευνητικό ινστιτούτο|ερευνητικό κέντρο|"
    r"επιστημονική έρευνα|ακαδημία επιστημών|αστεροσκοπείο|"
    # Turkish
    r"araştırma enstitüsü|araştırma laboratuvarı|"
    r"bilimsel araştırma|araştırma merkezi|"
    r"bilimler akademisi|astronomi gözlemevi|"
    # Estonian
    r"uurimisinstituut|teaduslaboratoorium|"
    r"teadusakadeemia|"
    # Latvian
    r"pētniecības institūts|zinātņu akadēmija|"
    # Lithuanian
    r"tyrimų institutas|mokslo akademija|"
    # Finnish
    r"tutkimuslaitos|tutkimuskeskus|tiedeakatemia|"
    # Swedish
    r"forskningsinstitut|forskningscenter|"
    r"vetenskapsakademi|"
    # Norwegian
    r"forskningsinstitutt|forskningssenter|"
    r"vitenskapsakademi|"
    # Danish
    r"forskningsinstitut|forskningscenter|"
    r"videnskabernes selskab|"
    # Persian
    r"موسسه تحقیقات|آزمایشگاه ملی|"
    r"مرکز پژوهشی|فرهنگستان علوم|"
    # Arabic
    r"معهد بحوث|معهد أبحاث|مختبر وطني|"
    r"البحث العلمي|أكاديمية العلوم|مرصد فلكي|"
    # Hebrew
    r"מכון מחקר|מעבדה מחקרית|"
    r"מחקר מדעי|אקדמיה למדעים|מצפה כוכבים|"
    # Hindi
    r"अनुसंधान संस्थान|वैज्ञानिक अनुसंधान|"
    r"विज्ञान अकादमी|"
    # Chinese (Simplified and Traditional)
    r"研究所|研究中心|实验室|實驗室|"
    r"科学研究|科學研究|"
    r"科学院|科學院|国家实验室|國家實驗室|"
    r"天文台|"
    # Japanese
    r"研究所|研究機関|科学研究|"
    r"科学アカデミー|国立研究所|天文台|"
    # Korean
    r"연구소|연구원|연구센터|"
    r"과학 연구|과학 아카데미|국립 연구소|천문대|"
    # Vietnamese
    r"viện nghiên cứu|trung tâm nghiên cứu|"
    r"nghiên cứu khoa học|viện hàn lâm khoa học|"
    # Thai
    r"สถาบันวิจัย|ศูนย์วิจัย|"
    r"การวิจัยทางวิทยาศาสตร์|"
    # Indonesian
    r"lembaga penelitian|pusat penelitian|"
    r"penelitian ilmiah|akademi sains|"
    # Malay
    r"institut penyelidikan|pusat penyelidikan|"
    # Catalan
    r"institut de recerca|centre de recerca|"
    r"recerca científica|acadèmia de ciències|"
    # Macedonian
    r"истражувачки институт|научно истражување|"
    r"академија на науките|опсерваторија|"
    # Belarusian
    r"навукова-даследчы інстытут|акадэмія навук|"
    r"абсерваторыя|"
    # Azerbaijani
    r"tədqiqat institutu|elmi tədqiqat|"
    r"elmlər akademiyası|astronomiya rəsədxanası|"
    # Georgian
    r"კვლევითი ინსტიტუტი|სამეცნიერო კვლევა|"
    r"მეცნიერებათა აკადემია|ობსერვატორია|"
    # Armenian
    r"հետազոտական ինստիտուտ|գիտական հետազոտություն|"
    r"գիտությունների ակադեմիա|աստղադիտարան|"
    # Kazakh
    r"зерттеу институты|ғылыми зерттеу|"
    r"ғылым академиясы|обсерватория|"
    # Uzbek
    r"tadqiqot instituti|ilmiy tadqiqot|"
    r"fanlar akademiyasi|"
    # Mongolian
    r"шинжилгээний хүрээлэн|шинжлэх ухааны академи|"
    # Khmer
    r"វិទ្យាស្ថានស្រាវជ្រាវ|ការស្រាវជ្រាវវិទ្យាសាស្ត្រ|"
    # Nepali
    r"अनुसन्धान संस्थान|वैज्ञानिक अनुसन्धान|"
    r"विज्ञान प्रज्ञा प्रतिष्ठान|"
    # Sinhala
    r"පර්යේෂණ ආයතනය|විද්‍යා පර්යේෂණ|"
    # Amharic
    r"የምርምር ተቋም|ሳይንሳዊ ምርምር|"
    # Maltese
    r"istitut ta' riċerka|riċerka xjentifika|"
    r"akkademja tax-xjenzi|"
    # Luxembourgish
    r"fuerschungsinstitut|wëssenschaftlech fuerschung|"
    # Haitian Creole
    r"enstiti rechèch|rechèch syantifik|"
    # Javanese
    r"lembaga penelitian|riset ilmiah|"
    # Cebuano
    r"institute sa pagsiksik|siyentipikong pagsiksik"
    r")\b"
)

SEARCH_ENGINE_RE = re.compile(
    r"(?i)\b("
    # English
    r"search engine|web search|internet search|"
    # Spanish
    r"buscador web|motor de búsqueda|"
    # Portuguese
    r"motor de busca|mecanismo de busca|buscador|"
    # French
    r"moteur de recherche|"
    # Italian
    r"motore di ricerca|"
    # German
    r"suchmaschine|websuche|"
    # Dutch
    r"zoekmachine|"
    # Polish
    r"wyszukiwarka internetowa|wyszukiwarka|"
    # Czech
    r"vyhledávač|internetový vyhledávač|"
    # Slovak
    r"vyhľadávač|internetový vyhľadávač|"
    # Russian
    r"поисковая система|поисковик|"
    # Ukrainian
    r"пошукова система|пошуковик|"
    # Bulgarian
    r"търсачка|интернет търсачка|"
    # Romanian
    r"motor de căutare|"
    # Hungarian
    r"keresőmotor|internetes kereső|"
    # Greek
    r"μηχανή αναζήτησης|"
    # Turkish
    r"arama motoru|web arama motoru|"
    # Croatian / Serbian / Bosnian
    r"tražilica|pretraživač|"
    # Slovenian
    r"iskalnik|spletni iskalnik|"
    # Estonian
    r"otsingumootor|"
    # Latvian
    r"meklētājprogramma|"
    # Lithuanian
    r"paieškos sistema|"
    # Finnish
    r"hakukone|"
    # Swedish
    r"sökmotor|"
    # Norwegian
    r"søkemotor|"
    # Danish
    r"søgemaskine|"
    # Persian
    r"موتور جستجو|"
    # Arabic
    r"محرك البحث|"
    # Hebrew
    r"מנוע חיפוש|"
    # Hindi
    r"खोज इंजन|"
    # Chinese (Simplified and Traditional)
    r"搜索引擎|搜尋引擎|"
    # Japanese
    r"検索エンジン|"
    # Korean
    r"검색 엔진|"
    # Vietnamese
    r"công cụ tìm kiếm|"
    # Thai
    r"เครื่องมือค้นหา|"
    # Indonesian
    r"mesin pencari|"
    # Malay
    r"enjin carian|"
    # Catalan
    r"motor de cerca|"
    # Macedonian
    r"пребарувач|интернет пребарувач|"
    # Belarusian
    r"пошукавая сістэма|"
    # Azerbaijani
    r"axtarış sistemi|veb axtarış|"
    # Georgian
    r"საძიებო სისტემა|"
    # Armenian
    r"որոնման համակարգ|"
    # Kazakh
    r"іздеу жүйесі|"
    # Uzbek
    r"qidiruv tizimi|"
    # Mongolian
    r"хайлтын систем|"
    # Khmer
    r"ម៉ាស៊ីនស្វែងរក|"
    # Burmese
    r"ရှာဖွေရေး အင်ဂျင်|"
    # Lao
    r"ເຄື່ອງມືຄົ້ນຫາ|"
    # Nepali
    r"खोज इन्जिन|"
    # Sinhala
    r"සෙවුම් යන්ත්‍රය|"
    # Amharic
    r"የፍለጋ ሞተር|"
    # Hausa
    r"injin bincike|"
    # Zulu
    r"injini yosesho|"
    # Maltese
    r"magna tat-tiftix|"
    # Luxembourgish
    r"sichmaschinn|"
    # Haitian Creole
    r"motè rechèch|"
    # Javanese
    r"mesin pencari|"
    # Cebuano
    r"makina sa pagpangita"
    r")\b"
)

SOCIAL_MEDIA_RE = re.compile(
    r"(?i)\b("
    # English
    r"social media platform|social network site|social networking|"
    r"online community platform|microblogging|"
    # Spanish
    r"red social|plataforma de redes sociales|"
    r"comunidad en línea|microblogging|"
    # Portuguese
    r"rede social|plataforma de redes sociais|"
    r"comunidade online|"
    # French
    r"réseau social|plateforme de médias sociaux|"
    r"communauté en ligne|microblogage|"
    # Italian
    r"rete sociale|piattaforma social|"
    r"community online|"
    # German
    r"soziales netzwerk|social[- ]media[- ]plattform|"
    r"online[- ]community|"
    # Dutch
    r"sociaal netwerk|sociale media[- ]platform|"
    # Polish
    r"sieć społecznościowa|portal społecznościowy|"
    r"platforma społecznościowa|"
    # Czech
    r"sociální síť|sociální platforma|"
    # Slovak
    r"sociálna sieť|sociálna platforma|"
    # Russian
    r"социальная сеть|платформа социальных сетей|"
    r"онлайн сообщество|"
    # Ukrainian
    r"соціальна мережа|"
    # Bulgarian
    r"социална мрежа|"
    # Romanian
    r"rețea de socializare|platformă socială|"
    # Hungarian
    r"közösségi háló|közösségi oldal|közösségi platform|"
    # Croatian / Serbian / Bosnian
    r"društvena mreža|"
    # Slovenian
    r"socialno omrežje|"
    # Greek
    r"κοινωνικό δίκτυο|μέσα κοινωνικής δικτύωσης|"
    # Turkish
    r"sosyal ağ|sosyal medya platformu|"
    # Albanian
    r"rrjet social|"
    # Estonian
    r"sotsiaalvõrgustik|sotsiaalmeedia platvorm|"
    # Latvian
    r"sociālais tīkls|"
    # Lithuanian
    r"socialinis tinklas|"
    # Finnish
    r"sosiaalinen media|sosiaalisen median palvelu|"
    # Swedish
    r"socialt nätverk|sociala medier[- ]plattform|"
    # Norwegian
    r"sosialt nettverk|"
    # Danish
    r"socialt netværk|"
    # Persian
    r"شبکه اجتماعی|"
    # Arabic
    r"شبكة اجتماعية|منصة تواصل اجتماعي|"
    r"وسائل التواصل الاجتماعي|"
    # Hebrew
    r"רשת חברתית|פלטפורמת מדיה חברתית|"
    # Hindi
    r"सोशल नेटवर्क|सोशल मीडिया प्लेटफॉर्म|"
    # Chinese (Simplified and Traditional)
    r"社交媒体|社交媒體|"
    r"社交网络|社交網絡|社交平台|"
    # Japanese
    r"ソーシャルメディア|ソーシャルネットワーク|"
    r"ソーシャルネットワーキング|"
    # Korean
    r"소셜 미디어|소셜 네트워크|"
    r"소셜 네트워킹 서비스|sns 플랫폼|"
    # Vietnamese
    r"mạng xã hội|nền tảng mạng xã hội|"
    # Thai
    r"เครือข่ายสังคม|โซเชียลมีเดีย|"
    # Indonesian
    r"jejaring sosial|media sosial|"
    # Malay
    r"rangkaian sosial|media sosial|"
    # Catalan
    r"xarxa social|"
    # Macedonian
    r"социјална мрежа|социјална платформа|"
    # Belarusian
    r"сацыяльная сетка|"
    # Azerbaijani
    r"sosial şəbəkə|sosial media platforması|"
    # Georgian
    r"სოციალური ქსელი|სოციალური მედიის პლატფორმა|"
    # Armenian
    r"սոցիալական ցանց|սոցիալական մեդիա հարթակ|"
    # Kazakh
    r"әлеуметтік желі|әлеуметтік медиа платформасы|"
    # Uzbek
    r"ijtimoiy tarmoq|ijtimoiy media platformasi|"
    # Mongolian
    r"нийгмийн сүлжээ|"
    # Khmer
    r"បណ្តាញសង្គម|"
    # Burmese
    r"လူမှုကွန်ရက်|"
    # Lao
    r"ເຄືອຂ່າຍສັງຄົມ|"
    # Nepali
    r"सामाजिक सञ्जाल|"
    # Sinhala
    r"සමාජ ජාලය|"
    # Amharic
    r"ማህበራዊ ሚዲያ|"
    # Yoruba
    r"àjọ̀ ìbáraẹnisọ̀rọ̀|"
    # Hausa
    r"hanyar sadarwar zamantakewa|"
    # Zulu
    r"inethiwekhi yezenhlalo|"
    # Maltese
    r"netwerk soċjali|pjattaforma tal-midja soċjali|"
    # Luxembourgish
    r"sozial netzwierk|"
    # Haitian Creole
    r"rezo sosyal|"
    # Javanese
    r"jaringan sosial|"
    # Cebuano
    r"social network|social media nga plataporma"
    r")\b"
)

SPORTS_RE = re.compile(
    r"(?i)\b("
    # English
    r"sports team|football club|soccer club|"
    r"baseball team|basketball team|hockey team|"
    r"sports league|athletic association|"
    r"sports federation|sporting goods|"
    r"rugby club|cricket club|tennis club|"
    r"national team|olympic committee|"
    # Spanish
    r"club deportivo|equipo de fútbol|"
    r"liga deportiva|federación deportiva|"
    r"artículos deportivos|comité olímpico|"
    # Portuguese
    r"clube de futebol|clube esportivo|"
    r"liga esportiva|federação esportiva|"
    r"artigos esportivos|comitê olímpico|"
    # French
    r"club sportif|club de football|"
    r"ligue sportive|fédération sportive|"
    r"articles de sport|comité olympique|"
    # Italian
    r"squadra di calcio|club sportivo|società sportiva|"
    r"lega sportiva|federazione sportiva|"
    r"articoli sportivi|comitato olimpico|"
    # German
    r"sportverein|fußballverein|sportclub|"
    r"sportliga|sportverband|sportartikel|"
    r"olympisches komitee|"
    # Dutch
    r"voetbalclub|sportclub|sportvereniging|"
    r"sportbond|sportartikelen|"
    # Polish
    r"klub piłkarski|klub sportowy|"
    r"liga sportowa|federacja sportowa|"
    r"artykuły sportowe|komitet olimpijski|"
    # Czech
    r"sportovní klub|fotbalový klub|"
    r"sportovní liga|sportovní federace|"
    r"sportovní potřeby|olympijský výbor|"
    # Slovak
    r"športový klub|futbalový klub|"
    r"športová liga|športová federácia|olympijský výbor|"
    # Russian
    r"спортивный клуб|футбольный клуб|"
    r"спортивная лига|спортивная федерация|"
    r"спортивные товары|олимпийский комитет|"
    # Ukrainian
    r"спортивний клуб|футбольний клуб|"
    r"спортивна ліга|олімпійський комітет|"
    # Bulgarian
    r"спортен клуб|футболен клуб|"
    r"спортна федерация|олимпийски комитет|"
    # Romanian
    r"club sportiv|club de fotbal|"
    r"ligă sportivă|federație sportivă|"
    r"articole sportive|comitet olimpic|"
    # Hungarian
    r"sportklub|labdarúgóklub|"
    r"sportliga|sportszövetség|"
    r"sportszerek|olimpiai bizottság|"
    # Croatian / Serbian / Bosnian
    r"sportski klub|nogometni klub|fudbalski klub|"
    r"sportska liga|sportski savez|"
    r"sportska oprema|olimpijski odbor|"
    # Slovenian
    r"športni klub|nogometni klub|"
    r"športna liga|športna zveza|"
    r"športna oprema|olimpijski komite|"
    # Greek
    r"αθλητικός σύλλογος|ποδοσφαιρικός σύλλογος|"
    r"αθλητική ομοσπονδία|αθλητικά είδη|"
    r"ολυμπιακή επιτροπή|"
    # Turkish
    r"spor kulübü|futbol kulübü|"
    r"spor ligi|spor federasyonu|"
    r"spor malzemeleri|olimpiyat komitesi|"
    # Albanian
    r"klub sportiv|klub futbolli|"
    r"federatë sportive|"
    # Estonian
    r"spordiklubi|jalgpalliklubi|"
    r"spordialaliit|olümpiakomitee|"
    # Latvian
    r"sporta klubs|futbola klubs|"
    r"sporta federācija|olimpiskā komiteja|"
    # Lithuanian
    r"sporto klubas|futbolo klubas|"
    r"sporto federacija|olimpinis komitetas|"
    # Finnish
    r"urheiluseura|jalkapalloseura|"
    r"urheiluliitto|urheilutarvikkeet|olympiakomitea|"
    # Swedish
    r"idrottsförening|fotbollsklubb|"
    r"idrottsförbund|sportartiklar|olympiska kommittén|"
    # Norwegian
    r"idrettsforening|fotballklubb|"
    r"idrettsforbund|sportsartikler|olympiske komité|"
    # Danish
    r"idrætsforening|fodboldklub|"
    r"idrætsforbund|sportsartikler|olympisk komité|"
    # Persian
    r"باشگاه ورزشی|باشگاه فوتبال|"
    r"فدراسیون ورزشی|کمیته المپیک|"
    # Arabic
    r"نادي رياضي|نادي كرة القدم|"
    r"اتحاد رياضي|أدوات رياضية|اللجنة الأولمبية|"
    # Hebrew
    r"מועדון ספורט|מועדון כדורגל|"
    r"איגוד ספורט|ועד אולימפי|"
    # Hindi
    r"खेल क्लब|फुटबॉल क्लब|"
    r"खेल संघ|खेल फेडरेशन|"
    # Bengali
    r"ক্রীড়া ক্লাব|ফুটবল ক্লাব|"
    # Chinese (Simplified and Traditional)
    r"体育俱乐部|足球俱乐部|體育俱樂部|足球俱樂部|"
    r"运动队|運動隊|体育联赛|體育聯賽|"
    r"体育用品|體育用品|奥委会|奧委會|"
    # Japanese
    r"スポーツクラブ|サッカークラブ|"
    r"スポーツリーグ|スポーツ連盟|"
    r"スポーツ用品|オリンピック委員会|"
    # Korean
    r"스포츠 클럽|축구 클럽|"
    r"스포츠 리그|스포츠 연맹|"
    r"스포츠 용품|올림픽 위원회|"
    # Vietnamese
    r"câu lạc bộ thể thao|câu lạc bộ bóng đá|"
    r"liên đoàn thể thao|ủy ban olympic|"
    # Thai
    r"สโมสรกีฬา|สโมสรฟุตบอล|"
    r"สหพันธ์กีฬา|คณะกรรมการโอลิมปิก|"
    # Indonesian
    r"klub olahraga|klub sepak bola|"
    r"liga olahraga|federasi olahraga|"
    r"perlengkapan olahraga|komite olimpiade|"
    # Malay
    r"kelab sukan|kelab bola sepak|"
    r"persatuan sukan|"
    # Catalan
    r"club esportiu|club de futbol|"
    r"federació esportiva|"
    # Macedonian
    r"спортски клуб|фудбалски клуб|"
    r"спортска лига|спортска федерација|"
    r"спортска опрема|олимписки комитет|"
    # Belarusian
    r"спартыўны клуб|футбольны клуб|"
    r"спартыўная ліга|спартыўная федэрацыя|"
    r"спартыўны інвентар|алімпійскі камітэт|"
    # Azerbaijani
    r"idman klubu|futbol klubu|"
    r"idman liqası|idman federasiyası|"
    r"idman ləvazimatları|olimpiya komitəsi|"
    # Georgian
    r"სპორტული კლუბი|საფეხბურთო კლუბი|"
    r"სპორტული ლიგა|სპორტული ფედერაცია|"
    r"სპორტული ინვენტარი|ოლიმპიური კომიტეტი|"
    # Armenian
    r"մարզական ակումբ|ֆուտբոլային ակումբ|"
    r"մարզական լիգա|մարզական ֆեդերացիա|"
    r"մարզական պարագաներ|օլիմպիական կոմիտե|"
    # Kazakh
    r"спорт клубы|футбол клубы|"
    r"спорт лигасы|спорт федерациясы|"
    r"спорт құралдары|олимпиада комитеті|"
    # Uzbek
    r"sport klubi|futbol klubi|"
    r"sport ligasi|sport federatsiyasi|"
    r"sport anjomlari|olimpiya qo'mitasi|"
    # Mongolian
    r"спортын клуб|хөлбөмбөгийн клуб|"
    r"спортын лиг|спортын холбоо|"
    r"олимпийн хороо|"
    # Khmer
    r"ក្លឹបកីឡា|ក្លឹបបាល់ទាត់|"
    r"សហព័ន្ធកីឡា|គណៈកម្មាធិការអូឡាំពិក|"
    # Burmese
    r"အားကစားကလပ်|ဘောလုံးကလပ်|"
    r"အားကစားအဖွဲ့ချုပ်|အိုလံပစ်ကော်မတီ|"
    # Lao
    r"ສະໂມສອນກິລາ|ສະໂມສອນບານເຕະ|"
    r"ສະຫະພັນກິລາ|ຄະນະກໍາມະການໂອລິມປິກ|"
    # Nepali
    r"खेल क्लब|फुटबल क्लब|"
    r"खेल लिग|खेल महासंघ|ओलम्पिक समिति|"
    # Sinhala
    r"ක්‍රීඩා සමාජය|පාපන්දු සමාජය|"
    r"ක්‍රීඩා සංගමය|ඔලිම්පික් කමිටුව|"
    # Amharic
    r"የስፖርት ክለብ|የእግር ኳስ ክለብ|"
    r"የስፖርት ፌዴሬሽን|የኦሊምፒክ ኮሚቴ|"
    # Yoruba
    r"ẹgbẹ́ ìdárayá|ẹgbẹ́ bọọlu afẹsẹgba|"
    r"àpapọ̀ ìdárayá|"
    # Hausa
    r"kungiyar wasanni|kungiyar kwallon kafa|"
    r"hadakar wasanni|kwamitin Olympiya|"
    # Igbo
    r"otu egwuregwu|otu bọọlụ ụkwụ|"
    r"otu egwuregwu mba|"
    # Zulu
    r"i-sports club|i-football club|"
    r"i-sports league|i-sports federation|"
    r"ikomidi le-Olympic|"
    # Pashto
    r"سپورت کلب|د فوټبال کلب|"
    r"د سپورت لیګ|د سپورت فدراسیون|"
    # Kurdish
    r"klûba werzişê|klûba futbolê|"
    r"federasyona werzişê|komîteya olîmpîk|"
    # Tajik
    r"клуби варзишӣ|клуби футбол|"
    r"федератсияи варзишӣ|кумитаи олимпӣ|"
    # Kyrgyz
    r"спорт клубу|футбол клубу|"
    r"спорт лигасы|олимпиада комитети|"
    # Maltese
    r"klabb sportiv|klabb tal-futbol|"
    r"federazzjoni sportiva|kumitat Olimpiku|"
    # Luxembourgish
    r"sportveräin|fussballveräin|"
    r"sportleague|sportverband|olympescht komitee|"
    # Haitian Creole
    r"klib espò|klib foutbòl|"
    r"federasyon espò|komite Olimpik|"
    # Frisian
    r"sportferiening|fuotbalclub|"
    r"sportbûn|"
    # Yiddish
    r"ספּאָרט קלוב|פוסבאל קלוב|"
    # Faroese
    r"ítróttafelag|"
    # Tatar
    r"спорт клубы|футбол клубы|"
    r"спорт федерациясе|"
    # Javanese
    r"klub olahraga|klub sepak bola|"
    r"federasi olahraga|"
    # Sundanese
    r"klub olahraga|"
    # Cebuano
    r"sports club|football club|"
    r"liga sa sports|federasyon sa sports"
    r")\b"
)

STAFFING_RE = re.compile(
    r"(?i)\b("
    # English
    r"staffing agency|staffing services|"
    r"recruitment agency|recruiting firm|"
    r"talent acquisition|placement agency|"
    r"temp agency|temporary staffing|"
    r"executive search|headhunter|headhunting|"
    r"employment agency|"
    # Spanish
    r"agencia de empleo|empresa de selección|"
    r"selección de personal|consultoría de recursos humanos|"
    r"búsqueda de ejecutivos|agencia de colocación|"
    # Portuguese
    r"agência de empregos|seleção de pessoal|"
    r"consultoria de recursos humanos|recrutamento e seleção|"
    # French
    r"agence de recrutement|cabinet de recrutement|"
    r"agence d'intérim|recherche de cadres|"
    r"placement de personnel|chasseur de têtes|"
    # Italian
    r"agenzia per il lavoro|agenzia di reclutamento|"
    r"ricerca e selezione|cacciatore di teste|"
    # German
    r"personalvermittlung|zeitarbeit|"
    r"personaldienstleister|personalberatung|"
    r"executive[- ]search|headhunter|"
    # Dutch
    r"uitzendbureau|wervings[- ]?en[- ]selectiebureau|"
    r"personeelsbemiddeling|"
    # Polish
    r"agencja pracy|agencja rekrutacyjna|"
    r"agencja pośrednictwa pracy|firma rekrutacyjna|"
    # Czech
    r"personální agentura|pracovní agentura|"
    r"náborová agentura|"
    # Slovak
    r"personálna agentúra|pracovná agentúra|"
    # Russian
    r"кадровое агентство|агентство по подбору персонала|"
    r"рекрутинговое агентство|подбор персонала|"
    r"executive search|"
    # Ukrainian
    r"кадрове агентство|рекрутингова агенція|"
    # Bulgarian
    r"агенция за подбор на персонал|агенция за временна заетост|"
    # Romanian
    r"agenție de recrutare|agenție de plasare|"
    r"firmă de recrutare|consultanță în resurse umane|"
    # Hungarian
    r"munkaerő-közvetítő|fejvadász|"
    r"toborzó iroda|személyzeti tanácsadó|"
    # Croatian / Serbian / Bosnian
    r"agencija za zapošljavanje|agencija za regrutaciju|"
    r"posredovanje pri zapošljavanju|"
    # Slovenian
    r"agencija za zaposlovanje|kadrovska agencija|"
    # Greek
    r"γραφείο ευρέσεως εργασίας|εταιρεία στελέχωσης|"
    r"υπηρεσίες ανθρώπινου δυναμικού|"
    # Turkish
    r"insan kaynakları şirketi|işe alım şirketi|"
    r"personel danışmanlığı|özel istihdam bürosu|"
    # Albanian
    r"agjenci punësimi|agjenci rekrutimi|"
    # Estonian
    r"personaliotsingu agentuur|tööhõiveagentuur|"
    # Latvian
    r"personāla atlases aģentūra|"
    # Lithuanian
    r"įdarbinimo agentūra|personalo atrankos agentūra|"
    # Finnish
    r"henkilöstöpalveluyritys|rekrytointitoimisto|"
    # Swedish
    r"bemanningsföretag|rekryteringsföretag|"
    # Norwegian
    r"bemanningsselskap|rekrutteringsselskap|"
    # Danish
    r"vikarbureau|rekrutteringsbureau|"
    # Persian
    r"آژانس استخدام|آژانس کاریابی|"
    # Arabic
    r"وكالة توظيف|شركة توظيف|"
    r"التوظيف والاستقطاب|"
    # Hebrew
    r"חברת השמה|חברת כוח אדם|חברת גיוס|"
    # Hindi
    r"भर्ती एजेंसी|रोजगार एजेंसी|"
    # Chinese (Simplified and Traditional)
    r"人力资源公司|人力資源公司|招聘公司|"
    r"猎头公司|獵頭公司|劳务派遣|勞務派遣|"
    # Japanese
    r"人材紹介|人材派遣|"
    r"ヘッドハンティング|転職エージェント|"
    # Korean
    r"인재 채용 회사|인재 파견|헤드헌팅|"
    # Vietnamese
    r"công ty tuyển dụng|công ty nhân sự|"
    # Thai
    r"บริษัทจัดหางาน|บริษัทรับสมัครงาน|"
    # Indonesian
    r"agensi tenaga kerja|agensi rekrutmen|perusahaan outsourcing|"
    # Malay
    r"agensi pekerjaan|agensi pengambilan|"
    # Catalan
    r"agència de col·locació|consultora de selecció|"
    # Macedonian
    r"агенција за вработување|агенција за регрутирање|"
    r"услуги за човечки ресурси|"
    # Belarusian
    r"кадравае агенцтва|агенцтва па падборы персаналу|"
    # Azerbaijani
    r"işə qəbul agentliyi|kadrlar agentliyi|"
    r"insan resursları məsləhətçiliyi|"
    # Georgian
    r"დასაქმების სააგენტო|კადრების სააგენტო|"
    r"ადამიანური რესურსების მომსახურება|"
    # Armenian
    r"հավաքագրման գործակալություն|կադրային գործակալություն|"
    # Kazakh
    r"кадр агенттігі|жалдау агенттігі|"
    # Uzbek
    r"kadrlar agentligi|ishga qabul qilish agentligi|"
    # Mongolian
    r"хүний нөөцийн агентлаг|"
    # Khmer
    r"ភ្នាក់ងារជ្រើសរើសបុគ្គលិក|"
    # Nepali
    r"रोजगार एजेन्सी|भर्ना एजेन्सी|"
    # Sinhala
    r"සේවා සැපයුම් ආයතනය|"
    # Amharic
    r"የቅጥር ኤጀንሲ|"
    # Hausa
    r"hukumar daukar ma'aikata|"
    # Zulu
    r"i-ejensi yokuqasha|"
    # Maltese
    r"aġenzija tar-reklutaġġ|aġenzija tax-xogħol|"
    # Luxembourgish
    r"perséinlechkeetsvermëttlung|recrutéieragentur|"
    # Haitian Creole
    r"ajans antrepriz|"
    # Javanese
    r"agensi rekrutmen|agensi tenaga kerja|"
    # Cebuano
    r"ahensya sa trabaho|ahensya sa rekrutment"
    r")\b"
)

TECHNOLOGY_RE = re.compile(
    r"(?i)\b("
    # English
    r"technology consulting|tech consulting|"
    r"software development|software company|"
    r"app development|mobile app development|"
    r"systems integrator|systems integration|"
    r"it services|information technology services|"
    # Spanish
    r"empresa de tecnología|desarrollo de software|"
    r"consultoría tecnológica|integrador de sistemas|"
    r"desarrollo de aplicaciones|servicios informáticos|"
    # Portuguese
    r"empresa de tecnologia|desenvolvimento de software|"
    r"consultoria de tecnologia|integrador de sistemas|"
    r"desenvolvimento de aplicativos|serviços de ti|"
    # French
    r"entreprise de technologie|développement de logiciels|"
    r"conseil en technologie|intégrateur de systèmes|"
    r"développement d'applications|services informatiques|"
    # Italian
    r"azienda tecnologica|sviluppo software|"
    r"consulenza tecnologica|integratore di sistemi|"
    r"sviluppo di applicazioni|servizi informatici|"
    # German
    r"technologieunternehmen|softwareentwicklung|"
    r"technologieberatung|systemintegrator|"
    r"app[- ]?entwicklung|it[- ]dienstleister|"
    # Dutch
    r"technologiebedrijf|softwareontwikkeling|"
    r"systeemintegrator|it[- ]dienstverlener|"
    # Polish
    r"firma technologiczna|tworzenie oprogramowania|"
    r"doradztwo technologiczne|integrator systemów|"
    r"tworzenie aplikacji|usługi it|"
    # Czech
    r"technologická společnost|vývoj softwaru|"
    r"systémový integrátor|vývoj aplikací|it služby|"
    # Slovak
    r"technologická spoločnosť|vývoj softvéru|"
    r"systémový integrátor|it služby|"
    # Russian
    r"технологическая компания|разработка программного обеспечения|"
    r"системный интегратор|разработка приложений|it[- ]услуги|"
    r"технологический консалтинг|"
    # Ukrainian
    r"технологічна компанія|розробка програмного забезпечення|"
    r"системний інтегратор|"
    # Bulgarian
    r"технологична компания|разработка на софтуер|"
    # Romanian
    r"companie de tehnologie|dezvoltare software|"
    r"integrator de sisteme|servicii it|"
    # Hungarian
    r"technológiai cég|szoftverfejlesztés|"
    r"rendszerintegrátor|alkalmazásfejlesztés|"
    # Croatian / Serbian / Bosnian
    r"tehnološka kompanija|razvoj softvera|"
    r"sistemski integrator|razvoj aplikacija|"
    # Slovenian
    r"tehnološko podjetje|razvoj programske opreme|"
    # Greek
    r"εταιρεία τεχνολογίας|ανάπτυξη λογισμικού|"
    r"υπηρεσίες πληροφορικής|ολοκληρωτής συστημάτων|"
    # Turkish
    r"teknoloji şirketi|yazılım geliştirme|"
    r"sistem entegratörü|uygulama geliştirme|bt hizmetleri|"
    # Albanian
    r"kompani teknologjie|zhvillim softueri|"
    # Estonian
    r"tehnoloogiaettevõte|tarkvaraarendus|"
    # Latvian
    r"tehnoloģiju uzņēmums|programmatūras izstrāde|"
    # Lithuanian
    r"technologijų įmonė|programinės įrangos kūrimas|"
    # Finnish
    r"teknologiayritys|ohjelmistokehitys|"
    r"järjestelmäintegraattori|sovelluskehitys|"
    # Swedish
    r"teknikföretag|mjukvaruutveckling|"
    r"systemintegratör|appspecialist|"
    # Norwegian
    r"teknologiselskap|programvareutvikling|"
    r"systemintegrator|appspecialist|"
    # Danish
    r"teknologivirksomhed|softwareudvikling|"
    r"systemintegrator|appudvikling|"
    # Persian
    r"شرکت فناوری|توسعه نرم افزار|"
    r"یکپارچه ساز سیستم|توسعه اپلیکیشن|"
    # Arabic
    r"شركة تكنولوجيا|تطوير البرمجيات|"
    r"تطوير التطبيقات|خدمات تقنية المعلومات|"
    # Hebrew
    r"חברת טכנולוגיה|פיתוח תוכנה|"
    r"אינטגרציית מערכות|פיתוח אפליקציות|"
    # Hindi
    r"प्रौद्योगिकी कंपनी|सॉफ्टवेयर विकास|"
    r"ऐप डेवलपमेंट|"
    # Bengali
    r"প্রযুক্তি কোম্পানি|সফটওয়্যার ডেভেলপমেন্ট|"
    # Chinese (Simplified and Traditional)
    r"科技公司|科技服务|科技服務|"
    r"软件开发|軟體開發|"
    r"系统集成|系統整合|"
    r"应用开发|應用開發|"
    r"信息技术服务|資訊科技服務|"
    # Japanese
    r"テクノロジー企業|ソフトウェア開発|"
    r"システムインテグレーター|アプリ開発|"
    r"it サービス|"
    # Korean
    r"기술 회사|소프트웨어 개발|"
    r"시스템 통합|앱 개발|it 서비스|"
    # Vietnamese
    r"công ty công nghệ|phát triển phần mềm|"
    r"tích hợp hệ thống|phát triển ứng dụng|"
    # Thai
    r"บริษัทเทคโนโลยี|พัฒนาซอฟต์แวร์|"
    r"พัฒนาแอปพลิเคชัน|"
    # Indonesian
    r"perusahaan teknologi|pengembangan perangkat lunak|"
    r"integrator sistem|pengembangan aplikasi|layanan ti|"
    # Malay
    r"syarikat teknologi|pembangunan perisian|"
    r"pembangunan aplikasi|"
    # Catalan
    r"empresa de tecnologia|desenvolupament de programari|"
    # Macedonian
    r"технолошка компанија|развој на софтвер|"
    r"систем интегратор|развој на апликации|"
    # Belarusian
    r"тэхналагічная кампанія|распрацоўка праграмнага забеспячэння|"
    r"сістэмны інтэгратар|"
    # Azerbaijani
    r"texnologiya şirkəti|proqram təminatının inkişafı|"
    r"sistem inteqratoru|tətbiqlərin inkişafı|"
    # Georgian
    r"ტექნოლოგიური კომპანია|პროგრამული უზრუნველყოფის შემუშავება|"
    r"სისტემური ინტეგრატორი|აპლიკაციების შემუშავება|"
    # Armenian
    r"տեխնոլոգիական ընկերություն|ծրագրերի մշակում|"
    r"համակարգային ինտեգրատոր|հավելվածների մշակում|"
    # Kazakh
    r"технологиялық компания|бағдарламалық қамтамасыз етуді әзірлеу|"
    r"жүйелік интегратор|қосымшаларды әзірлеу|"
    # Uzbek
    r"texnologiya kompaniyasi|dasturiy ta'minotni ishlab chiqish|"
    r"tizim integratori|"
    # Mongolian
    r"технологийн компани|программ хангамж хөгжүүлэлт|"
    # Khmer
    r"ក្រុមហ៊ុនបច្ចេកវិទ្យា|ការអភិវឌ្ឍន៍កម្មវិធី|"
    # Burmese
    r"နည်းပညာ ကုမ္ပဏီ|ဆော့ဖ်ဝဲ ဖွံ့ဖြိုးတိုးတက်မှု|"
    # Lao
    r"ບໍລິສັດເທັກໂນໂລຢີ|ການພັດທະນາຊອບແວ|"
    # Nepali
    r"प्रविधि कम्पनी|सफ्टवेयर विकास|"
    # Sinhala
    r"තාක්ෂණ සමාගම|මෘදුකාංග සංවර්ධනය|"
    # Amharic
    r"የቴክኖሎጂ ኩባንያ|የሶፍትዌር ልማት|"
    # Yoruba
    r"ilé iṣẹ́ ìmọ̀ iṣẹ́ ọnà|"
    # Hausa
    r"kamfanin fasaha|haɓaka manhaja|"
    # Zulu
    r"inkampani yobuchwepheshe|ukuthuthukiswa kwesofthiwe|"
    # Pashto
    r"د ټکنالوژۍ شرکت|د سافټویر پراختیا|"
    # Kurdish
    r"şirketa teknolojiyê|geşepêdana nivîsbariyê|"
    # Tajik
    r"ширкати технологӣ|таҳияи нармафзор|"
    # Kyrgyz
    r"технологиялык компания|программалык камсыздоону иштеп чыгуу|"
    # Maltese
    r"kumpanija teknoloġika|żvilupp tas-software|"
    r"integratur tas-sistemi|"
    # Luxembourgish
    r"technologiefirma|software entwécklung|"
    # Haitian Creole
    r"konpayi teknoloji|devlopman lojisyèl|"
    # Frisian
    r"technologybedriuw|softwareûntwikkeling|"
    # Javanese
    r"perusahaan teknologi|pengembangan perangkat lunak|"
    # Cebuano
    r"kompaniya sa teknolohiya|pag-uswag sa software"
    r")\b"
)

UTILITIES_RE = re.compile(
    r"(?i)\b("
    # English
    r"electric utility|electricity provider|electric power|"
    r"power company|gas utility|natural gas utility|"
    r"water utility|water authority|public utility|"
    r"municipal utility|electricity distribution|"
    r"sewer authority|wastewater authority|"
    # Spanish
    r"compañía eléctrica|cooperativa de electricidad|"
    r"distribuidora eléctrica|empresa de aguas|"
    r"empresa de gas|servicio público|servicios públicos|"
    # Portuguese
    r"companhia elétrica|distribuidora de energia|"
    r"empresa de saneamento|empresa de água|"
    r"companhia de gás|concessionária de energia|"
    r"serviço público|"
    # French
    r"compagnie d'électricité|distributeur d'électricité|"
    r"compagnie des eaux|distributeur de gaz|"
    r"service public|régie municipale|"
    # Italian
    r"società elettrica|distributore di energia|"
    r"azienda del gas|azienda dei servizi idrici|"
    r"servizi pubblici|"
    # German
    r"energieversorger|stromversorger|"
    r"gasversorger|wasserversorger|"
    r"stadtwerke|öffentliche versorgung|"
    # Dutch
    r"energieleverancier|elektriciteitsleverancier|"
    r"waterbedrijf|gasleverancier|nutsbedrijf|"
    # Polish
    r"przedsiębiorstwo energetyczne|"
    r"zakład energetyczny|przedsiębiorstwo wodociągowe|"
    r"zakład gazowniczy|usługi publiczne|"
    # Czech
    r"energetická společnost|distributor elektřiny|"
    r"vodárenská společnost|plynárenská společnost|"
    # Slovak
    r"energetická spoločnosť|distribútor elektriny|"
    r"vodárenská spoločnosť|plynárenská spoločnosť|"
    # Russian
    r"электроэнергетическая компания|"
    r"энергоснабжающая организация|"
    r"электросетевая компания|водоканал|"
    r"газоснабжающая организация|коммунальные услуги|"
    # Ukrainian
    r"електроенергетична компанія|"
    r"водоканал|газопостачання|"
    # Bulgarian
    r"електроразпределение|водоснабдяване|газоразпределение|"
    # Romanian
    r"distribuitor de energie electrică|"
    r"compania de apă|distribuitor de gaze|"
    r"servicii de utilități publice|"
    # Hungarian
    r"áramszolgáltató|villamosenergia szolgáltató|"
    r"vízszolgáltató|gázszolgáltató|közszolgáltatás|"
    # Croatian / Serbian / Bosnian
    r"elektrodistribucija|elektroprivreda|"
    r"vodovod i kanalizacija|gradska plinara|"
    r"komunalne usluge|"
    # Slovenian
    r"elektrodistribucija|elektrogospodarstvo|"
    r"vodovodno podjetje|plinsko podjetje|"
    r"komunalno podjetje|"
    # Greek
    r"εταιρεία ηλεκτρισμού|εταιρεία ύδρευσης|"
    r"εταιρεία φυσικού αερίου|κοινής ωφελείας|"
    # Turkish
    r"elektrik dağıtım şirketi|elektrik şirketi|"
    r"su idaresi|doğalgaz dağıtım|kamu hizmeti|"
    # Albanian
    r"shoqëria elektroenergjetike|"
    r"shoqëria e ujësjellësit|"
    # Estonian
    r"elektriettevõte|veevärk|gaasiettevõte|"
    # Latvian
    r"elektroapgādes uzņēmums|ūdensapgādes uzņēmums|"
    # Lithuanian
    r"elektros tiekimo įmonė|vandens tiekimo įmonė|"
    # Finnish
    r"sähköyhtiö|vesilaitos|kaasuyhtiö|"
    # Swedish
    r"elbolag|elnätsbolag|vattenbolag|gasbolag|"
    # Norwegian
    r"strømleverandør|kraftselskap|"
    r"vannverk|gassleverandør|"
    # Danish
    r"elselskab|vandværk|gasselskab|"
    # Persian
    r"شرکت برق|شرکت آب|شرکت گاز|"
    # Arabic
    r"شركة الكهرباء|شركة المياه|شركة الغاز|"
    r"المرافق العامة|"
    # Hebrew
    r"חברת חשמל|חברת מים|חברת גז|תשתיות|"
    # Hindi
    r"बिजली कंपनी|जल कंपनी|"
    # Chinese (Simplified and Traditional)
    r"电力公司|電力公司|供水公司|燃气公司|燃氣公司|"
    r"自来水公司|自來水公司|"
    r"天然气公司|天然氣公司|"
    r"公用事业|公用事業|"
    # Japanese
    r"電力会社|ガス会社|水道会社|"
    r"公益事業|"
    # Korean
    r"전력 회사|가스 회사|수도 회사|공기업|"
    # Vietnamese
    r"công ty điện lực|công ty cấp nước|"
    r"công ty khí đốt|tiện ích công cộng|"
    # Thai
    r"การไฟฟ้า|การประปา|"
    # Indonesian
    r"perusahaan listrik|perusahaan air|perusahaan gas|"
    # Malay
    r"syarikat elektrik|syarikat air|syarikat gas|"
    # Catalan
    r"companyia elèctrica|companyia d'aigua|"
    # Macedonian
    r"електрична компанија|водовод|"
    r"гасна компанија|комунални услуги|"
    # Belarusian
    r"электрычная кампанія|водаканал|"
    r"газавая кампанія|камунальныя паслугі|"
    # Azerbaijani
    r"elektrik şirkəti|sukanal|"
    r"qaz şirkəti|kommunal xidmətlər|"
    # Georgian
    r"ელექტრო კომპანია|წყალარინება|"
    r"გაზის კომპანია|კომუნალური მომსახურება|"
    # Armenian
    r"էլեկտրական ընկերություն|ջրանցույց|"
    r"գազի ընկերություն|կոմունալ ծառայություններ|"
    # Kazakh
    r"электр компаниясы|сумен жабдықтау|"
    r"газ компаниясы|коммуналдық қызметтер|"
    # Uzbek
    r"elektr kompaniyasi|suv ta'minoti|"
    r"gaz kompaniyasi|kommunal xizmatlar|"
    # Mongolian
    r"эрчим хүчний компани|усан хангамж|"
    # Khmer
    r"ក្រុមហ៊ុនអគ្គិសនី|ក្រុមហ៊ុនទឹក|"
    # Burmese
    r"လျှပ်စစ် ကုမ္ပဏီ|ရေသန့်ရေးကုမ္ပဏီ|"
    # Lao
    r"ບໍລິສັດໄຟຟ້າ|ນ້ຳປະປາ|"
    # Nepali
    r"विद्युत कम्पनी|खानेपानी कम्पनी|"
    # Sinhala
    r"විදුලි සමාගම|ජල සැපයුම්|"
    # Amharic
    r"የኤሌክትሪክ ኩባንያ|የውሃ ኩባንያ|"
    # Maltese
    r"kumpanija tal-elettriku|kumpanija tal-ilma|"
    r"kumpanija tal-gass|servizzi pubbliċi|"
    # Luxembourgish
    r"elektrizitéitsfirma|waasserbetrib|"
    r"gasfirma|"
    # Haitian Creole
    r"konpayi elektrisite|konpayi dlo|"
    r"konpayi gaz|sèvis piblik|"
    # Frisian
    r"elektrisiteitsbedriuw|wettersuksessje|"
    # Javanese
    r"perusahaan listrik|perusahaan air|"
    # Cebuano
    r"kompaniya sa elektrisidad|kompaniya sa tubig"
    r")\b"
)

# Energy — non-utility energy companies (gas distributors, oil & gas
# downstream, energy services). Distinct from Utilities, which is
# regulated power/water. Recommended new category for the README. Until
# the README adds "Energy", classify these as "Utilities" via the
# wiring at the bottom.
ENERGY_RE = re.compile(
    r"(?i)\b("
    # English
    r"energy company|energy services|energy solutions|"
    r"energy provider|gas distribution|natural gas distribution|"
    r"renewable energy company|solar energy company|"
    r"wind energy company|"
    r"oil exploration|petroleum company|"
    # Spanish
    r"empresa de energía|servicios energéticos|"
    r"soluciones energéticas|energía renovable|"
    r"energía solar|energía eólica|petrolera|"
    # Portuguese
    r"empresa de energia|serviços de energia|"
    r"soluções energéticas|energia renovável|"
    r"energia solar|energia eólica|petrolífera|"
    # French
    r"entreprise énergétique|services énergétiques|"
    r"solutions énergétiques|énergie renouvelable|"
    r"énergie solaire|énergie éolienne|pétrolière|"
    # Italian
    r"azienda energetica|servizi energetici|"
    r"soluzioni energetiche|energia rinnovabile|"
    r"energia solare|energia eolica|petrolifera|"
    # German
    r"energieunternehmen|energiedienstleister|"
    r"energielösungen|erneuerbare energien|"
    r"solarenergie|windenergie|"
    # Dutch
    r"energiebedrijf|energiediensten|"
    r"hernieuwbare energie|zonne[- ]energie|windenergie|"
    # Polish
    r"firma energetyczna|rozwiązania energetyczne|"
    r"energia odnawialna|energia słoneczna|"
    r"energia wiatrowa|"
    # Czech
    r"energetická společnost|energetické služby|"
    r"obnovitelná energie|solární energie|větrná energie|"
    # Slovak
    r"energetická spoločnosť|energetické služby|"
    r"obnoviteľná energia|solárna energia|"
    # Russian
    r"энергетическая компания|"
    r"энергетические услуги|энергетические решения|"
    r"возобновляемая энергия|солнечная энергетика|"
    r"ветроэнергетика|нефтегазовая компания|"
    # Ukrainian
    r"енергетична компанія|відновлювана енергія|"
    # Bulgarian
    r"енергийна компания|възобновяема енергия|"
    # Romanian
    r"companie energetică|servicii energetice|"
    r"energie regenerabilă|energie solară|energie eoliană|"
    # Hungarian
    r"energiatársaság|energiaszolgáltató|"
    r"megújuló energia|napenergia|szélenergia|"
    # Croatian / Serbian / Bosnian
    r"energetska kompanija|obnovljivi izvori|"
    r"solarna energija|energija vjetra|"
    # Slovenian
    r"energetsko podjetje|obnovljivi viri|"
    r"sončna energija|vetrna energija|"
    # Greek
    r"ενεργειακή εταιρεία|ανανεώσιμη ενέργεια|"
    r"ηλιακή ενέργεια|αιολική ενέργεια|"
    # Turkish
    r"enerji şirketi|enerji hizmetleri|"
    r"yenilenebilir enerji|güneş enerjisi|rüzgar enerjisi|"
    # Albanian
    r"kompani energjie|"
    # Estonian
    r"energiaettevõte|taastuvenergia|"
    # Latvian
    r"enerģijas uzņēmums|atjaunojamā enerģija|"
    # Lithuanian
    r"energijos įmonė|atsinaujinanti energija|"
    # Finnish
    r"energiayhtiö|uusiutuva energia|"
    r"aurinkoenergia|tuulivoima|"
    # Swedish
    r"energibolag|förnybar energi|"
    r"solenergi|vindkraft|"
    # Norwegian
    r"energiselskap|fornybar energi|"
    r"solenergi|vindkraft|"
    # Danish
    r"energiselskab|vedvarende energi|"
    r"solenergi|vindkraft|"
    # Persian
    r"شرکت انرژی|انرژی تجدیدپذیر|انرژی خورشیدی|"
    # Arabic
    r"شركة طاقة|الطاقة المتجددة|"
    r"الطاقة الشمسية|طاقة الرياح|"
    # Hebrew
    r"חברת אנרגיה|אנרגיה מתחדשת|אנרגיה סולארית|"
    # Hindi
    r"ऊर्जा कंपनी|नवीकरणीय ऊर्जा|सौर ऊर्जा|"
    # Chinese (Simplified and Traditional)
    r"能源公司|能源服务|能源服務|"
    r"可再生能源|太阳能|太陽能|"
    r"风能|風能|新能源|"
    # Japanese
    r"エネルギー会社|再生可能エネルギー|"
    r"太陽光発電|風力発電|"
    # Korean
    r"에너지 회사|재생 에너지|태양광 에너지|풍력 에너지|"
    # Vietnamese
    r"công ty năng lượng|năng lượng tái tạo|"
    r"năng lượng mặt trời|năng lượng gió|"
    # Thai
    r"บริษัทพลังงาน|พลังงานหมุนเวียน|"
    r"พลังงานแสงอาทิตย์|"
    # Indonesian
    r"perusahaan energi|energi terbarukan|"
    r"energi surya|energi angin|"
    # Malay
    r"syarikat tenaga|tenaga boleh diperbaharui|"
    r"tenaga suria|tenaga angin|"
    # Catalan
    r"empresa d'energia|energia renovable|"
    # Macedonian
    r"енергетска компанија|обновлива енергија|"
    r"сончева енергија|ветерна енергија|"
    # Belarusian
    r"энергетычная кампанія|аднаўляльная энергія|"
    r"сонечная энергія|"
    # Azerbaijani
    r"enerji şirkəti|bərpaolunan enerji|"
    r"günəş enerjisi|külək enerjisi|"
    # Georgian
    r"ენერგეტიკული კომპანია|განახლებადი ენერგია|"
    r"მზის ენერგია|ქარის ენერგია|"
    # Armenian
    r"էներգետիկ ընկերություն|վերականգնվող էներգիա|"
    r"արևային էներգիա|հողմային էներգիա|"
    # Kazakh
    r"энергетикалық компания|жаңартылатын энергия|"
    r"күн энергиясы|жел энергиясы|"
    # Uzbek
    r"energiya kompaniyasi|qayta tiklanadigan energiya|"
    r"quyosh energiyasi|shamol energiyasi|"
    # Mongolian
    r"эрчим хүчний компани|сэргээгдэх эрчим хүч|"
    r"нарны эрчим хүч|салхины эрчим хүч|"
    # Khmer
    r"ក្រុមហ៊ុនថាមពល|ថាមពលកកើតឡើងវិញ|"
    r"ថាមពលព្រះអាទិត្យ|"
    # Burmese
    r"စွမ်းအင် ကုမ္ပဏီ|ပြန်လည်ပြည့်ဖြိုးမြဲ စွမ်းအင်|"
    r"နေရောင်ခြည် စွမ်းအင်|"
    # Lao
    r"ບໍລິສັດພະລັງງານ|ພະລັງງານທົດແທນ|"
    # Nepali
    r"ऊर्जा कम्पनी|नवीकरणीय ऊर्जा|"
    r"सौर्य ऊर्जा|"
    # Sinhala
    r"බලශක්ති සමාගම|පුනර්ජනනීය බලශක්තිය|"
    # Amharic
    r"የኢነርጂ ኩባንያ|ታዳሽ ኢነርጂ|"
    # Maltese
    r"kumpanija tal-enerġija|enerġija rinnovabbli|"
    r"enerġija solari|enerġija mir-riħ|"
    # Luxembourgish
    r"energiefirma|erneierbar energie|"
    r"sonnenenergie|wandkraaft|"
    # Haitian Creole
    r"konpayi enèji|enèji renouvlab|"
    r"enèji solè|"
    # Frisian
    r"enerzjybedriuw|fernijbere enerzjy|"
    # Javanese
    r"perusahaan energi|energi terbarukan|"
    # Cebuano
    r"kompaniya sa enerhiya|enerhiya nga gibag-o"
    r")\b"
)

# Government Media — state-owned broadcasters / press agencies
GOV_MEDIA_RE = re.compile(
    r"(?i)\b("
    # English
    r"state media|state[- ]owned (?:broadcaster|television)|"
    r"public broadcaster|national broadcaster|"
    r"state news agency|public service broadcaster|"
    r"state-funded media|"
    # Spanish
    r"medios estatales|emisora pública|"
    r"radiotelevisión pública|televisión estatal|"
    r"radiodifusión pública|"
    # Portuguese
    r"emissora pública|radiodifusão pública|"
    r"televisão estatal|empresa pública de comunicação|"
    # French
    r"radiodiffuseur public|télévision publique|"
    r"service public audiovisuel|média de service public|"
    # Italian
    r"emittente pubblica|servizio pubblico radiotelevisivo|"
    r"televisione di stato|"
    # German
    r"öffentlich-rechtlicher rundfunk|"
    r"öffentlich-rechtliche anstalt|"
    r"staatlicher rundfunk|staatsfernsehen|"
    # Dutch
    r"publieke omroep|staatsomroep|"
    # Polish
    r"telewizja publiczna|radio publiczne|"
    r"nadawca publiczny|publiczna radiofonia|"
    # Czech
    r"veřejnoprávní vysílatel|veřejnoprávní rozhlas|"
    r"veřejnoprávní televize|"
    # Slovak
    r"verejnoprávny vysielateľ|verejnoprávna televízia|"
    # Russian
    r"государственное СМИ|общественное вещание|"
    r"государственное телевидение|государственный канал|"
    # Ukrainian
    r"державне ТБ|суспільне мовлення|"
    # Bulgarian
    r"обществена медия|държавна телевизия|"
    # Romanian
    r"televiziune publică|radiodifuzor public|"
    r"presă de stat|"
    # Hungarian
    r"közmédia|közszolgálati média|"
    r"közszolgálati televízió|"
    # Croatian / Serbian / Bosnian
    r"javni servis|javna radiotelevizija|"
    r"državna televizija|"
    # Slovenian
    r"javna radiotelevizija|javni medijski servis|"
    # Greek
    r"κρατική τηλεόραση|δημόσιος ραδιοτηλεοπτικός|"
    r"δημόσια ραδιοτηλεόραση|"
    # Turkish
    r"kamu yayıncısı|devlet televizyonu|"
    r"devlet yayın kuruluşu|"
    # Estonian
    r"avalik-õiguslik ringhääling|"
    # Latvian
    r"sabiedriskais medijs|"
    # Lithuanian
    r"visuomeninis transliuotojas|"
    # Finnish
    r"julkisen palvelun media|yleisradio|"
    # Swedish
    r"public service|statsmedier|"
    # Norwegian
    r"allmennkringkaster|statlige medier|"
    # Danish
    r"public service|statslige medier|"
    # Persian
    r"رسانه دولتی|صدا و سیمای دولتی|"
    # Arabic
    r"الإعلام الرسمي|التلفزيون الحكومي|"
    r"وكالة الأنباء الرسمية|"
    # Hebrew
    r"שידור ציבורי|תקשורת ממלכתית|"
    # Hindi
    r"सरकारी मीडिया|सार्वजनिक प्रसारक|"
    # Chinese (Simplified and Traditional)
    r"国有媒体|國有媒體|"
    r"国家广播|國家廣播|"
    r"官方媒体|官方媒體|公共广播|公共廣播|"
    # Japanese
    r"公共放送|国営放送|国営メディア|"
    # Korean
    r"공영방송|국영 방송|국영 매체|"
    # Vietnamese
    r"đài truyền hình quốc gia|truyền thông nhà nước|"
    # Indonesian
    r"penyiaran publik|media negara|"
    # Malay
    r"penyiaran awam|media kerajaan|"
    # Thai
    r"สื่อของรัฐ|สถานีโทรทัศน์ของรัฐ|"
    # Macedonian
    r"државни медиуми|јавен сервис|"
    # Belarusian
    r"дзяржаўныя СМІ|грамадскае вяшчанне|"
    # Azerbaijani
    r"dövlət mediası|ictimai yayım|"
    # Georgian
    r"სახელმწიფო მედია|საზოგადოებრივი მაუწყებლობა|"
    # Armenian
    r"պետական լրատվամիջոցներ|հանրային հեռարձակում|"
    # Kazakh
    r"мемлекеттік БАҚ|қоғамдық хабар тарату|"
    # Uzbek
    r"davlat ommaviy axborot vositalari|jamoat eshittirishi|"
    # Mongolian
    r"төрийн мэдээлэл|олон нийтийн нэвтрүүлэг|"
    # Nepali
    r"सरकारी सञ्चार|"
    # Maltese
    r"midja tal-istat|xandir pubbliku|"
    # Luxembourgish
    r"staatlech medien|öffentlech-rechtleche rundfunk|"
    # Haitian Creole
    r"medya leta|"
    # Javanese
    r"media negara|penyiaran publik|"
    # Cebuano
    r"media sa estado"
    r")\b"
)

# Industrial — broader than Manufacturing; chemicals, mining, metals,
# heavy industry where the operator isn't strictly a maker.
INDUSTRIAL_RE = re.compile(
    r"(?i)\b("
    # English
    r"mining (?:company|services|operations)|metals and mining|"
    r"chemicals industry|industrial chemicals|"
    r"oil and gas|petroleum|petrochemical|"
    r"heavy industry|industrial company|industrial services|"
    r"industrial group|industrial conglomerate|"
    # Spanish
    r"industria pesada|empresa minera|industria petroquímica|"
    r"compañía petrolera|grupo industrial|"
    r"productos químicos industriales|industria química|"
    # Portuguese
    r"indústria pesada|petroquímica|companhia mineradora|"
    r"empresa de mineração|grupo industrial|"
    r"produtos químicos industriais|indústria química|"
    # French
    r"industrie lourde|société minière|pétrochimie|"
    r"compagnie pétrolière|groupe industriel|"
    r"produits chimiques industriels|industrie chimique|"
    # Italian
    r"industria pesante|petrolchimica|"
    r"azienda mineraria|gruppo industriale|"
    r"prodotti chimici industriali|industria chimica|"
    # German
    r"schwerindustrie|bergbauunternehmen|petrochemie|"
    r"erdölgesellschaft|industriekonzern|"
    r"industriechemie|chemische industrie|"
    # Dutch
    r"zware industrie|mijnbouw[- ]?onderneming|"
    r"petrochemie|chemische industrie|"
    # Polish
    r"przemysł ciężki|spółka wydobywcza|"
    r"petrochemia|grupa przemysłowa|przemysł chemiczny|"
    # Czech
    r"těžký průmysl|těžební společnost|"
    r"petrochemický průmysl|chemický průmysl|"
    # Slovak
    r"ťažký priemysel|baníctvo|"
    r"petrochemický priemysel|chemický priemysel|"
    # Russian
    r"тяжелая промышленность|тяжёлая промышленность|"
    r"горнодобывающая компания|горно-обогатительный|"
    r"нефтехимия|нефтегазовая компания|"
    r"нефтяная компания|химическая промышленность|"
    # Ukrainian
    r"важка промисловість|гірничодобувна компанія|"
    r"нафтогазова компанія|"
    # Bulgarian
    r"тежка промишленост|минна компания|"
    r"петрохимия|химическа промишленост|"
    # Romanian
    r"industria grea|companie minieră|"
    r"petrochimie|industrie chimică|"
    # Hungarian
    r"nehézipar|bányavállalat|"
    r"petrolkémia|vegyipar|"
    # Croatian / Serbian / Bosnian
    r"teška industrija|rudarska kompanija|"
    r"petrokemija|hemijska industrija|"
    # Slovenian
    r"težka industrija|rudarsko podjetje|"
    r"petrokemija|kemična industrija|"
    # Greek
    r"βαριά βιομηχανία|μεταλλευτική εταιρεία|"
    r"πετροχημική|χημική βιομηχανία|"
    # Turkish
    r"ağır sanayi|maden şirketi|"
    r"petrokimya|kimya sanayi|"
    # Albanian
    r"industri e rëndë|"
    # Estonian
    r"raske tööstus|kaevandus|petrokeemia|"
    # Latvian
    r"smagā rūpniecība|kalnrūpniecība|petroķīmija|"
    # Lithuanian
    r"sunkioji pramonė|kasybos įmonė|"
    r"naftos chemija|chemijos pramonė|"
    # Finnish
    r"raskasteollisuus|kaivosyhtiö|petrokemia|"
    # Swedish
    r"tung industri|gruvbolag|petrokemi|"
    # Norwegian
    r"tungindustri|gruveselskap|petrokjemi|"
    # Danish
    r"tungindustri|mineselskab|petrokemi|"
    # Persian
    r"صنایع سنگین|شرکت معدن|پتروشیمی|"
    # Arabic
    r"الصناعات الثقيلة|شركة تعدين|"
    r"البتروكيماويات|الصناعة الكيماوية|"
    # Hebrew
    r"תעשייה כבדה|חברת כרייה|"
    r"פטרוכימיה|תעשייה כימית|"
    # Hindi
    r"भारी उद्योग|खनन कंपनी|पेट्रोकेमिकल|"
    # Chinese (Simplified and Traditional)
    r"重工业|重工業|矿业公司|礦業公司|石化|"
    r"化工产业|化工產業|"
    r"石油公司|采矿|採礦|"
    # Japanese
    r"重工業|鉱業|石油化学|"
    r"化学工業|採掘業|"
    # Korean
    r"중공업|광업|석유화학|화학 산업|"
    # Vietnamese
    r"công nghiệp nặng|công ty khai khoáng|"
    r"hóa dầu|công nghiệp hóa chất|"
    # Thai
    r"อุตสาหกรรมหนัก|บริษัทเหมืองแร่|ปิโตรเคมี|"
    # Indonesian
    r"industri berat|perusahaan tambang|"
    r"petrokimia|industri kimia|"
    # Malay
    r"industri berat|syarikat perlombongan|petrokimia|"
    # Catalan
    r"indústria pesada|empresa minera|petroquímica|"
    # Macedonian
    r"тешка индустрија|рударска компанија|"
    r"петрохемија|хемиска индустрија|"
    # Belarusian
    r"цяжкая прамысловасць|горназдабыўная кампанія|"
    r"нафтахімія|хімічная прамысловасць|"
    # Azerbaijani
    r"ağır sənaye|mədən şirkəti|"
    r"neft kimyası|kimya sənayesi|"
    # Georgian
    r"მძიმე მრეწველობა|სამთო კომპანია|"
    r"ნავთობქიმია|ქიმიური მრეწველობა|"
    # Armenian
    r"ծանր արդյունաբերություն|հանքարդյունաբերական ընկերություն|"
    r"նավթաքիմիա|քիմիական արդյունաբերություն|"
    # Kazakh
    r"ауыр өнеркәсіп|тау-кен компаниясы|"
    r"мұнай-химия|химия өнеркәсібі|"
    # Uzbek
    r"og'ir sanoat|kon kompaniyasi|"
    r"neft kimyo|kimyo sanoati|"
    # Mongolian
    r"хүнд үйлдвэр|уул уурхайн компани|"
    r"нефтийн хими|химийн үйлдвэр|"
    # Khmer
    r"ឧស្សាហកម្មធុនធ្ងន់|ក្រុមហ៊ុនរ៉ែ|"
    r"ឧស្សាហកម្មគីមី|"
    # Burmese
    r"လေးလံသော လုပ်ငန်း|သတ္တုတွင်း ကုမ္ပဏီ|"
    r"ပီထရိုကြီမီကယ်|ဓာတုဗေဒ လုပ်ငန်း|"
    # Lao
    r"ອຸດສາຫະກໍາຫນັກ|ບໍລິສັດຂຸດຄົ້ນແຮ່|"
    r"ປີໂຕເຄມີ|ອຸດສາຫະກໍາເຄມີ|"
    # Nepali
    r"भारी उद्योग|खान कम्पनी|"
    r"पेट्रोरसायन|रसायन उद्योग|"
    # Sinhala
    r"බර කර්මාන්තය|ඛනිජ සමාගම|"
    r"ඛනිජ තෙල් රසායනික|"
    # Amharic
    r"ከባድ ኢንዱስትሪ|የማዕድን ኩባንያ|"
    r"የነዳጅ ኬሚካል ኢንዱስትሪ|"
    # Yoruba
    r"ìṣe iṣẹ́ wúwo|ilé iṣẹ́ ìwakùsa|"
    r"ìṣe ohun fẹ́rọ́ olómi|"
    # Hausa
    r"masana'antu masu nauyi|kamfanin hakar ma'adinai|"
    r"sinadarai na man fetur|"
    # Igbo
    r"ụlọ ọrụ dị arọ|ụlọ ọrụ ngwuputa ihe|"
    # Zulu
    r"izimboni ezisindayo|inkampani yezimayini|"
    r"ipethrokhemikhali|imboni yamakhemikhali|"
    # Pashto
    r"دروند صنعت|د کانونو شرکت|"
    r"پټروشیمي|د کیمیا صنعت|"
    # Kurdish
    r"pîşesaziya giran|şirketa madenê|"
    r"petrokîmya|pîşesaziya kîmyewî|"
    # Tajik
    r"саноати вазнин|ширкати истихроҷи маъдан|"
    r"кимиёи нафт|саноати кимиёвӣ|"
    # Kyrgyz
    r"оор өнөр жай|тоо-кен компаниясы|"
    r"нефть химиясы|"
    # Maltese
    r"industrija peżanti|kumpanija tal-minjieri|"
    r"petrokimika|industrija kimika|"
    # Luxembourgish
    r"schwierindustrie|biergbauunternehmen|"
    r"petrochimie|chemesch industrie|"
    # Haitian Creole
    r"endistri lou|konpayi min|"
    r"petwochimik|endistri chimik|"
    # Frisian
    r"swiere yndustry|mynbouwûnderneming|"
    # Yiddish
    r"שווערע אינדוסטריע|"
    # Faroese
    r"tungur ídnaður|"
    # Tatar
    r"авыр сәнәгать|казу-чыгару компаниясе|"
    # Javanese
    r"industri berat|perusahaan pertambangan|"
    # Sundanese
    r"industri beurat|"
    # Cebuano
    r"industriya nga bug-at|kompaniya sa pagmina"
    r")\b"
)

# IaaS — explicit infrastructure clouds (compute, storage). Bare "cloud"
# is handled by Web Host; this catches when the page specifically markets
# IaaS-style primitives.
IAAS_RE = re.compile(
    r"(?i)\b("
    # English
    r"\biaas\b|infrastructure[ -]as[ -]a[ -]service|"
    r"public cloud|private cloud platform|"
    r"compute and storage cloud|cloud compute|"
    # Spanish
    r"infraestructura como servicio|nube pública|"
    r"plataforma de nube privada|"
    # Portuguese
    r"infraestrutura como serviço|nuvem pública|"
    r"plataforma de nuvem privada|"
    # French
    r"infrastructure en tant que service|cloud public|"
    r"plateforme de cloud privé|"
    # Italian
    r"infrastruttura come servizio|cloud pubblico|"
    r"piattaforma cloud privata|"
    # German
    r"infrastruktur als dienst|public[- ]cloud|"
    r"private[- ]cloud[- ]plattform|"
    # Dutch
    r"infrastructuur als dienst|publieke cloud|private cloud[- ]platform|"
    # Polish
    r"infrastruktura jako usługa|chmura publiczna|"
    r"platforma chmury prywatnej|"
    # Czech
    r"infrastruktura jako služba|veřejný cloud|"
    # Slovak
    r"infraštruktúra ako služba|verejný cloud|"
    # Russian
    r"инфраструктура как услуга|публичное облако|"
    r"платформа частного облака|"
    # Turkish
    r"hizmet olarak altyapı|genel bulut|"
    r"özel bulut platformu|"
    # Romanian
    r"infrastructură ca serviciu|cloud public|"
    # Hungarian
    r"szolgáltatott infrastruktúra|publikus felhő|"
    # Greek
    r"υποδομή ως υπηρεσία|δημόσιο cloud|"
    # Arabic
    r"البنية التحتية كخدمة|السحابة العامة|"
    # Hebrew
    r"תשתית כשירות|ענן ציבורי|"
    # Persian
    r"زیرساخت به عنوان سرویس|"
    # Chinese (Simplified and Traditional)
    r"基础设施即服务|基礎設施即服務|"
    r"公有云|公有雲|"
    r"私有云平台|私有雲平台|"
    # Japanese
    r"インフラサービス|"
    r"パブリッククラウド|プライベートクラウド|"
    # Korean
    r"인프라 서비스|퍼블릭 클라우드|프라이빗 클라우드|"
    # Vietnamese
    r"hạ tầng dưới dạng dịch vụ|đám mây công cộng|"
    # Indonesian
    r"infrastruktur sebagai layanan|cloud publik"
    r")\b"
)

# PaaS — explicit platforms-as-a-service
PAAS_RE = re.compile(
    r"(?i)\b("
    # English
    r"\bpaas\b|platform[ -]as[ -]a[ -]service|"
    r"app platform|developer platform|"
    r"backend as a service|baas\b|"
    # Spanish
    r"plataforma como servicio|"
    r"plataforma de aplicaciones|plataforma para desarrolladores|"
    # Portuguese
    r"plataforma como serviço|"
    r"plataforma de aplicações|plataforma para desenvolvedores|"
    # French
    r"plateforme en tant que service|"
    r"plateforme d'applications|plateforme pour développeurs|"
    # Italian
    r"piattaforma come servizio|"
    r"piattaforma per applicazioni|piattaforma per sviluppatori|"
    # German
    r"plattform als dienst|"
    r"app[- ]plattform|entwicklerplattform|"
    # Dutch
    r"platform als dienst|app[- ]platform|ontwikkelaarsplatform|"
    # Polish
    r"platforma jako usługa|platforma aplikacji|"
    r"platforma dla programistów|"
    # Czech
    r"platforma jako služba|aplikační platforma|"
    # Slovak
    r"platforma ako služba|aplikačná platforma|"
    # Russian
    r"платформа как услуга|платформа для приложений|"
    r"платформа для разработчиков|"
    # Turkish
    r"hizmet olarak platform|uygulama platformu|"
    r"geliştirici platformu|"
    # Romanian
    r"platformă ca serviciu|platformă pentru dezvoltatori|"
    # Hungarian
    r"szolgáltatott platform|alkalmazás platform|"
    # Greek
    r"πλατφόρμα ως υπηρεσία|"
    # Arabic
    r"المنصة كخدمة|منصة المطورين|"
    # Hebrew
    r"פלטפורמה כשירות|"
    # Persian
    r"پلتفرم به عنوان سرویس|"
    # Chinese (Simplified and Traditional)
    r"平台即服务|平台即服務|"
    r"应用平台|應用平台|"
    r"开发者平台|開發者平台|"
    # Japanese
    r"プラットフォームサービス|アプリプラットフォーム|"
    r"開発者プラットフォーム|"
    # Korean
    r"플랫폼 서비스|앱 플랫폼|개발자 플랫폼|"
    # Vietnamese
    r"nền tảng dưới dạng dịch vụ|nền tảng ứng dụng|"
    # Indonesian
    r"platform sebagai layanan"
    r")\b"
)

# SaaS — explicit software platforms / verticalized SaaS
SAAS_RE = re.compile(
    r"(?i)\b("
    # English
    r"\bsaas\b|software[ -]as[ -]a[ -]service|"
    r"all[- ]in[- ]one platform|"
    r"crm platform|erp platform|hrm platform|hcm platform|"
    r"workflow automation platform|workforce management platform|"
    r"saas company|saas solution|"
    # Spanish
    r"software como servicio|plataforma todo en uno|"
    r"plataforma crm|plataforma erp|"
    r"plataforma de automatización de flujos|"
    # Portuguese
    r"software como serviço|plataforma tudo em um|"
    r"plataforma crm|plataforma erp|"
    r"plataforma de automação de fluxos|"
    # French
    r"logiciel en tant que service|plateforme tout en un|"
    r"plateforme crm|plateforme erp|"
    r"plateforme d'automatisation des flux|"
    # Italian
    r"software come servizio|piattaforma tutto in uno|"
    r"piattaforma crm|piattaforma erp|"
    # German
    r"software als dienst|all[- ]in[- ]one[- ]plattform|"
    r"crm[- ]plattform|erp[- ]plattform|"
    r"workflow[- ]automatisierungsplattform|"
    # Dutch
    r"software als dienst|alles[- ]in[- ]één platform|"
    # Polish
    r"oprogramowanie jako usługa|platforma wszystko w jednym|"
    r"platforma crm|platforma erp|"
    # Czech
    r"software jako služba|platforma vše v jednom|"
    # Slovak
    r"softvér ako služba|"
    # Russian
    r"программное обеспечение как услуга|"
    r"платформа всё в одном|crm[- ]платформа|erp[- ]платформа|"
    # Turkish
    r"hizmet olarak yazılım|hepsi bir arada platform|"
    r"crm platformu|erp platformu|"
    # Romanian
    r"software ca serviciu|platformă all-in-one|"
    # Hungarian
    r"szolgáltatott szoftver|"
    # Greek
    r"λογισμικό ως υπηρεσία|"
    # Arabic
    r"البرمجيات كخدمة|منصة شاملة|"
    # Hebrew
    r"תוכנה כשירות|"
    # Persian
    r"نرم افزار به عنوان سرویس|"
    # Chinese (Simplified and Traditional)
    r"软件即服务|軟體即服務|"
    r"一体化平台|一體化平台|"
    r"crm 平台|erp 平台|"
    # Japanese
    r"ソフトウェアサービス|"
    r"オールインワンプラットフォーム|"
    r"crm プラットフォーム|erp プラットフォーム|"
    # Korean
    r"소프트웨어 서비스|올인원 플랫폼|"
    r"crm 플랫폼|erp 플랫폼|"
    # Vietnamese
    r"phần mềm dưới dạng dịch vụ|"
    # Indonesian
    r"perangkat lunak sebagai layanan"
    r")\b"
)

# Conglomerate — diversified holding companies. Hard to detect well from
# page text; keep narrow to avoid noise.
CONGLOMERATE_RE = re.compile(
    r"(?i)\b("
    # English
    r"multinational conglomerate|diversified conglomerate|"
    r"holding company|holdings group|"
    # Spanish
    r"grupo empresarial diversificado|conglomerado multinacional|"
    r"sociedad de cartera|grupo holding|"
    # Portuguese
    r"conglomerado empresarial|conglomerado multinacional|"
    r"sociedade gestora de participações|grupo holding|"
    # French
    r"groupe diversifié|conglomérat multinational|"
    r"société holding|société de portefeuille|"
    # Italian
    r"gruppo diversificato|conglomerato multinazionale|"
    r"società di partecipazioni|holding finanziaria|"
    # German
    r"mischkonzern|holdinggesellschaft|"
    r"beteiligungsgesellschaft|holding[- ]?gruppe|"
    # Dutch
    r"holdingmaatschappij|gediversifieerd concern|"
    # Polish
    r"konglomerat|spółka holdingowa|grupa holdingowa|"
    # Czech
    r"holdingová společnost|holdingová skupina|"
    # Slovak
    r"holdingová spoločnosť|"
    # Russian
    r"конгломерат|холдинговая компания|"
    r"диверсифицированная группа|холдинг[- ]группа|"
    # Ukrainian
    r"холдингова компанія|"
    # Bulgarian
    r"холдингово дружество|холдингова група|"
    # Romanian
    r"companie holding|grup holding|conglomerat multinational|"
    # Hungarian
    r"holdingtársaság|holding csoport|"
    # Croatian / Serbian / Bosnian
    r"holding kompanija|holding grupa|"
    # Slovenian
    r"holdinška družba|"
    # Greek
    r"εταιρεία συμμετοχών|όμιλος εταιρειών|"
    # Turkish
    r"holding şirketi|çok uluslu holding|"
    r"yatırım holding|"
    # Albanian
    r"kompani holding|"
    # Estonian
    r"valdusettevõte|"
    # Latvian
    r"holdinga sabiedrība|"
    # Lithuanian
    r"holdingo bendrovė|"
    # Finnish
    r"holdingyhtiö|monialayhtiö|"
    # Swedish
    r"holdingbolag|investmentbolag|"
    # Norwegian
    r"holdingselskap|"
    # Danish
    r"holdingselskab|"
    # Persian
    r"شرکت هلدینگ|"
    # Arabic
    r"شركة قابضة|مجموعة قابضة|تكتل|"
    # Hebrew
    r"חברת אחזקות|תאגיד רב לאומי|"
    # Hindi
    r"होल्डिंग कंपनी|समूह|"
    # Chinese (Simplified and Traditional)
    r"多元化集团|多元化集團|"
    r"控股公司|集团公司|集團公司|"
    # Japanese
    r"複合企業|持株会社|コングロマリット|"
    # Korean
    r"복합 기업|지주 회사|"
    # Vietnamese
    r"tập đoàn đa ngành|công ty cổ phần holding|"
    # Indonesian
    r"perusahaan induk|grup konglomerasi|"
    # Malay
    r"syarikat induk|kumpulan korporat"
    r")\b"
)

PRIVACY_ORG_RE = re.compile(
    r"(?i)^(domain protection services|registration private|"
    r"perfect privacy|privacy service|privacy protection|"
    r"data redacted|not disclosed|domain admin|domain administrator|"
    r"statutory masking|registry services|proxy protection|"
    r"privacy-protect|privacy protect|domains by proxy|"
    r"gdpr masked|withheld for privacy|"
    r"on behalf of|personal data,|contact privacy|"
    r"redacted|name redacted|"
    r"super privacy service|tieredaccess\.com|"
    r"private whois|private registration)"
)

TITLE_NOISE_RE = re.compile(
    r"(?i)^(welcome|home|главная|首页|ホーム|홈|"
    r"index|index of|"
    r"page d'accueil|"
    r"untitled|loading|page is loading|"
    r"login|sign[ -]in|"
    r"under construction|coming soon|"
    r"just a moment|access denied|forbidden|"
    r"вход|"
    r"vercel security checkpoint|cloudflare|"
    r"website is for sale|domain is for sale|domain (?:name )?for sale|"
    r"buy this domain)"
)

LEGAL_SUFFIX_RE = re.compile(
    r"(?i),?\s*("
    r"LLC|L\.L\.C\.|"
    r"Inc\.?|Incorporated|"
    r"Corp\.?|Corporation|"
    r"Ltd\.?|Limited|Pte\.? Ltd\.?|Pty\.? Ltd\.?|Pte Ltd|"
    r"GmbH|UG|AG|KG|"
    r"S\.?A\.?|S\.?A\.?S\.?|S\.?A\.?R\.?L\.?|S\.?L\.?|S\.?R\.?L\.?|"
    r"Sp\. ?z o\.?o\.?|spólka z o\.o\.|sp z o\.o|sp\.\s?z\.?o\.?o|"
    r"OOO|ООО|ZAO|JSC|"
    r"Ltda\.?|EIRELI|EIRELI ME|ME|"
    r"d\.o\.o\.|d\.d\.|"
    r"Pvt\.? Ltd\.?|Private Limited|"
    r"S\. ?de R\.L\.|S\. ?de R\.L\. de C\.V\.|"
    r"NV|N\.V\.|BV|B\.V\.|AB|AS|A/S|Oy|"
    r"S\.?p\.?A\.?|"
    r"Co\.?,? Ltd\.?|Company Limited|"
    r"k\.k\.|株式会社|"
    r"Sdn\.? Bhd\.?|"
    r"S\.C\.|s\.c\.|"
    r"s\.c\.a\.? r\.l\.?|s\.c\. ?a r\.?l\.?|"
    r"UAB|"
    r"Cooperativa|"
    r"Compañía Limitada|Sociedad Limitada|"
    r"C\.A\.|"
    r"Druzstvo|"
    r"Spólka Jawna|spolka jawna"
    r")\.?\s*$"
)

# Strip leading legal-form prefixes like "PT.", "LLC", "OOO", etc.
LEGAL_PREFIX_RE = re.compile(
    r"(?i)^("
    r"LLC|L\.L\.C\.|"
    r"PT\.?|"
    r"OOO|ООО|ZAO|JSC|"
    r"Pvt\.? Ltd\.?|"
    r"S\.?C\.?|"
    r"S\.?p\.?A\.?"
    r")\s+"
)


def clean_brand(s: str) -> str:
    if not s:
        return ""
    # Don't strip trailing dots / commas BEFORE the suffix regex — the
    # regex wants to see "L.L.C." with its trailing period to match.
    s = s.strip()
    for _ in range(4):
        new = LEGAL_SUFFIX_RE.sub("", s).strip().strip(".,").strip()
        new = LEGAL_PREFIX_RE.sub("", new).strip().strip(".,").strip()
        if new == s:
            break
        s = new
    return s


def derive_brand_from_domain(domain: str) -> str:
    parts = domain.split(".")
    base = parts[0]
    if len(base) < 2:
        return ""
    tokens = re.split(r"[-_]", base)
    return "-".join(t.capitalize() for t in tokens if t)


def is_privacy_org(org: str) -> bool:
    if not org:
        return True
    return bool(PRIVACY_ORG_RE.match(org.strip()))


def is_noise_title(title: str) -> bool:
    if not title:
        return True
    return bool(TITLE_NOISE_RE.match(title.strip()))


def extract_title_brand(title: str, domain_root: str = "") -> str:
    """Extract the brand from a page title.

    Many sites format the title as "Page name | Brand" or "Brand | Page name".
    When the domain root looks like one of the title segments, prefer that
    one regardless of position. Otherwise fall back to the first segment.

    If the title has no separator, return ``""`` rather than the whole title —
    a separator-less title is usually a single-line marketing sentence
    ("Bem Vindo! Metro Network, serviços para provedor de internet") and is
    unsafe to use as a canonical brand name.
    """
    if not title:
        return ""
    for sep in (" - ", " | ", " — ", " :: ", "::", " // ", " · ", " – "):
        if sep in title:
            parts = [p.strip() for p in title.split(sep) if p.strip()]
            if not parts:
                continue
            if domain_root:
                root_simple = re.sub(r"[^a-z0-9]", "", domain_root.lower())
                for p in parts:
                    p_simple = re.sub(r"[^a-z0-9]", "", p.lower())
                    if p_simple and (
                        root_simple in p_simple or p_simple in root_simple
                    ):
                        return p
            return parts[0]
    return ""


def normalize_caps(s: str) -> str:
    """Title-case a string that's all caps, leave mixed-case alone."""
    if not s:
        return s
    if s == s.upper() and re.search(r"[A-Za-z]", s):
        # Title-case but preserve initialisms (anything ≤3 letters stays)
        return " ".join(w if len(w) <= 3 else w.title() for w in s.split())
    return s


def _domain_root(domain: str) -> str:
    """Return the leftmost label of the base domain, lowercased."""
    return domain.split(".")[0].lower()


def pick_brand(row: dict, domain: str, as_name: str) -> str:
    title = fix_text(row.get("title", "").strip())
    domain_root = _domain_root(domain)
    title_brand = ""
    if title and not is_noise_title(title):
        title_brand = clean_brand(extract_title_brand(title, domain_root))

    # Prefer the title brand when the domain root is a substring of it (or
    # vice versa). This catches the common "MMDB names a holding company,
    # but the operator brand is in the title" case (e.g. accessmontana.com
    # has as_name "MONTANA WEST, L.L.C." but title "Access Montana").
    root = _domain_root(domain).replace("-", "")
    if title_brand and 2 <= len(title_brand) <= 80:
        tb_simple = re.sub(r"[^a-z0-9]", "", title_brand.lower())
        if tb_simple and (root in tb_simple or tb_simple in root):
            return title_brand

    # Otherwise: as_name → title → WHOIS → domain
    if as_name and len(as_name) >= 3:
        b = clean_brand(as_name)
        b = normalize_caps(b)
        if b and len(b) >= 2:
            return b
    if title_brand and 2 <= len(title_brand) <= 80:
        return title_brand
    org = row.get("whois_org", "").strip()
    if org and not is_privacy_org(org):
        b = clean_brand(org)
        b = normalize_caps(b)
        if b and len(b) >= 2:
            return b
    return derive_brand_from_domain(domain)


def auto_classify(row: dict, domain: str, as_name: str) -> tuple | None:
    title = fix_text(row.get("title", ""))
    desc = fix_text(row.get("description", ""))
    text = f"{title} {desc}"

    # Need *some* signal to classify (text or as_name)
    if not (title or desc) and not as_name:
        return None

    is_isp = bool(ISP_RE.search(text)) or bool(ISP_RE.search(as_name))
    is_host = bool(WEB_HOST_RE.search(text)) or bool(WEB_HOST_RE.search(as_name))
    is_edu = bool(EDUCATION_RE.search(text)) or domain.endswith(
        (
            ".edu",
            ".edu.au",
            ".ac.uk",
            ".ac.in",
            ".ac.jp",
            ".ac.kr",
            ".ac.za",
            ".ac.nz",
            ".edu.mx",
            ".edu.br",
            ".edu.tr",
            ".edu.cn",
            ".edu.tw",
            ".edu.sg",
            ".edu.my",
            ".edu.ph",
            ".edu.eg",
        )
    )
    is_gov = bool(GOV_RE.search(text)) or any(
        domain.endswith(s)
        for s in (
            ".gov",
            ".gov.uk",
            ".gov.au",
            ".gov.in",
            ".gov.br",
            ".go.kr",
            ".go.id",
            ".go.th",
            ".gob.mx",
            ".gob.cl",
            ".gob.ar",
            ".gob.gt",
            ".gov.cn",
            ".gov.za",
            ".gov.tr",
            ".gv.at",
            ".admin.ch",
        )
    )
    is_health = bool(HEALTHCARE_RE.search(text))
    is_retail = bool(RETAIL_RE.search(text))
    is_manuf = bool(MANUFACTURING_RE.search(text))
    is_travel = bool(TRAVEL_RE.search(text))
    is_food = bool(FOOD_RE.search(text))
    is_legal = bool(LEGAL_RE.search(text))
    is_realestate = bool(REAL_ESTATE_RE.search(text))
    is_finance = bool(FINANCE_RE.search(text))
    is_auto = bool(AUTOMOTIVE_RE.search(text))
    is_ent = bool(ENTERTAINMENT_RE.search(text))
    # Additional industry detectors
    is_email_security = bool(EMAIL_SECURITY_RE.search(text))
    is_marketing = bool(MARKETING_RE.search(text))
    is_email_provider = bool(EMAIL_PROVIDER_RE.search(text))
    is_agriculture = bool(AGRICULTURE_RE.search(text))
    is_beauty = bool(BEAUTY_RE.search(text))
    is_construction = bool(CONSTRUCTION_RE.search(text))
    is_consulting = bool(CONSULTING_RE.search(text))
    is_defense = bool(DEFENSE_RE.search(text))
    is_event = bool(EVENT_PLANNING_RE.search(text))
    is_logistics = bool(LOGISTICS_RE.search(text))
    is_mssp = bool(MSSP_RE.search(text))
    is_news = bool(NEWS_RE.search(text))
    is_nonprofit = bool(NONPROFIT_RE.search(text))
    is_photography = bool(PHOTOGRAPHY_RE.search(text))
    is_physical_security = bool(PHYSICAL_SECURITY_RE.search(text))
    is_print = bool(PRINT_RE.search(text))
    is_publishing = bool(PUBLISHING_RE.search(text))
    is_religion = bool(RELIGION_RE.search(text))
    is_science = bool(SCIENCE_RE.search(text))
    is_search = bool(SEARCH_ENGINE_RE.search(text))
    is_social = bool(SOCIAL_MEDIA_RE.search(text))
    is_sports = bool(SPORTS_RE.search(text))
    is_staffing = bool(STAFFING_RE.search(text))
    is_tech = bool(TECHNOLOGY_RE.search(text))
    is_utilities = bool(UTILITIES_RE.search(text))
    is_energy = bool(ENERGY_RE.search(text))
    is_gov_media = bool(GOV_MEDIA_RE.search(text))
    is_industrial = bool(INDUSTRIAL_RE.search(text))
    is_iaas = bool(IAAS_RE.search(text))
    is_paas = bool(PAAS_RE.search(text))
    is_saas = bool(SAAS_RE.search(text))
    is_conglomerate = bool(CONGLOMERATE_RE.search(text))

    brand = pick_brand(row, domain, as_name)
    if not brand:
        return None

    # If as_name has telecom-y vocabulary even without page text, classify as ISP.
    # "Communications" / "Network" alone are too generic (Christian Broadcasting
    # Network, CNN, etc.) — guard against media context. Add only words that
    # virtually always mean internet access.
    has_media_context = bool(
        re.search(
            r"(?i)\b(broadcasting|broadcaster|media group|television|"
            r"tv (?:station|channel|network)|radio|"
            r"news network|news media|publishing|"
            r"medya grup|媒体)\b",
            f"{title} {desc} {as_name}",
        )
    )
    if not (is_isp or is_host or is_edu or is_gov or is_health):
        if re.search(
            r"(?i)\b(telecom|broadband|fiber|fibre|wifi|wi-fi|wireless|"
            r"telecomunica|telekommunika|telcom|telekom|wisp|catv|voip|"
            r"telephone (?:co\.?|company|cooperative)|"
            r"cable internet|cable broadband|cablevision|"
            r"cellular|mobile network|satellite communications|"
            r"мoбильн|телекомм|интернет|"
            r"internet services?|\binternet\b)",
            as_name,
        ):
            is_isp = True
        elif not has_media_context and re.search(
            r"(?i)\b(communications?|cable)\b", as_name
        ):
            # "Granite State Communications", "Saicom Voice Services" → ISP
            # but "Christian Broadcasting Network" is filtered by the media guard
            is_isp = True
        elif re.search(
            r"(?i)\b(hosting|webhost|veebimajutus|datacenter|data centre|rechenzentrum)\b",
            as_name,
        ):
            is_host = True
        elif re.search(
            r"(?i)\b(university|college|institute|академ|académie)\b", as_name
        ):
            is_edu = True
        elif re.search(
            r"(?i)\b(managed it|managed services?|it solutions?|it support|"
            r"managed network|managed wifi|"
            r"managed (?:tech|technology))\b",
            f"{title} {desc}",
        ):
            # vmi.se, odyssey.uk, marconet.com type
            return (brand, "MSP")
        elif re.search(r"(?i)\b(bank|banca|banco|banque)\b", as_name):
            return (brand, "Finance")

    # Per README precedence: Email Security > Marketing > ISP > Web Host >
    # Email Provider > SaaS > industry. The first three win over network
    # operator types when matched.
    if is_email_security:
        return (brand, "Email Security")
    if is_marketing:
        return (brand, "Marketing")
    # Healthcare wins over Education when both match (e.g. "University Health Network")
    if is_health:
        return (brand, "Healthcare")
    if is_isp:
        return (brand, "ISP")
    if is_host:
        return (brand, "Web Host")
    # IaaS / PaaS / SaaS sit between Web Host and Email Provider — explicit
    # cloud-tier matches before falling to industry.
    if is_iaas:
        return (brand, "IaaS")
    if is_paas:
        return (brand, "PaaS")
    if is_saas:
        return (brand, "SaaS")
    if is_email_provider:
        return (brand, "Email Provider")
    if is_edu:
        return (brand, "Education")
    if is_gov:
        return (brand, "Government")
    if is_gov_media:
        return (brand, "Government Media")
    if is_mssp:
        return (brand, "MSSP")
    # Finance via body text catches insurance, investment, asset mgmt, etc.
    # — categories that the narrow as_name `bank|banca|...` fallback misses.
    if is_finance:
        return (brand, "Finance")
    # Industry-tier — order by signal specificity / typical false-positive
    # risk. More-specific keywords first; broader / fuzzier last.
    if is_defense:
        return (brand, "Defense")
    if is_legal:
        return (brand, "Legal")
    if is_news:
        return (brand, "News")
    if is_publishing:
        return (brand, "Publishing")
    if is_print:
        return (brand, "Print")
    if is_photography:
        return (brand, "Photography")
    if is_physical_security:
        return (brand, "Physical Security")
    if is_religion:
        return (brand, "Religion")
    if is_science:
        return (brand, "Science")
    if is_search:
        return (brand, "Search Engine")
    if is_social:
        return (brand, "Social Media")
    if is_sports:
        return (brand, "Sports")
    if is_staffing:
        return (brand, "Staffing")
    if is_event:
        return (brand, "Event Planning")
    if is_travel:
        return (brand, "Travel")
    if is_realestate:
        return (brand, "Real Estate")
    if is_logistics:
        return (brand, "Logistics")
    if is_food:
        return (brand, "Food")
    if is_auto:
        return (brand, "Automotive")
    if is_beauty:
        return (brand, "Beauty")
    if is_construction:
        return (brand, "Construction")
    if is_agriculture:
        return (brand, "Agriculture")
    if is_utilities:
        return (brand, "Utilities")
    if is_energy:
        # README does not yet define an "Energy" type; map non-utility
        # energy companies to Utilities until that's added.
        return (brand, "Utilities")
    if is_nonprofit:
        return (brand, "Nonprofit")
    if is_ent:
        return (brand, "Entertainment")
    if is_manuf:
        return (brand, "Manufacturing")
    if is_industrial:
        return (brand, "Industrial")
    if is_consulting:
        return (brand, "Consulting")
    if is_tech:
        return (brand, "Technology")
    if is_retail:
        return (brand, "Retail")
    if is_conglomerate:
        return (brand, "Conglomerate")
    return None


def _load_mmdb_as_names(mmdb_path: str) -> dict:
    """Return {as_domain.lower(): as_name} from the MMDB.

    For domains with multiple ASNs the first as_name encountered wins; that
    is acceptable because we only use the as_name as a brand hint, not as
    authoritative attribution.
    """
    out: dict = {}
    with maxminddb.open_database(mmdb_path) as reader:
        for net, rec in reader:
            if net.version != 4 or not isinstance(rec, dict):
                continue
            d = rec.get("as_domain")
            n = rec.get("as_name")
            if d and n:
                key = d.lower()
                if key not in out:
                    out[key] = n
    return out


def classify_tsv(input_path: str, mmdb_path: str) -> tuple:
    """Classify every row of a collect_domain_info.py TSV.

    Returns ``(adds, ku, stats)`` where ``adds`` is a list of
    ``(domain, name, type)`` tuples for the map, ``ku`` is the list of
    domains that didn't classify, and ``stats`` is a dict of counters.
    """
    asn = _load_mmdb_as_names(mmdb_path)
    adds: list = []
    ku: list = []
    auto = hand = 0
    with open(input_path, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f, delimiter="\t")
        for row in reader:
            domain = row["domain"].strip().lower()
            as_name = asn.get(domain, "")
            if domain in HAND:
                decision = HAND[domain]
                if decision == "KU":
                    ku.append(domain)
                elif decision is None:
                    pass
                else:
                    adds.append((domain, decision[0], decision[1]))
                    hand += 1
                continue
            r = auto_classify(row, domain, as_name)
            if r:
                adds.append((domain, r[0], r[1]))
                auto += 1
            else:
                ku.append(domain)
    return adds, ku, {"auto": auto, "hand": hand, "ku": len(ku)}


def main():
    p = argparse.ArgumentParser(description=(__doc__ or "").strip().splitlines()[0])
    p.add_argument(
        "-i",
        "--input",
        required=True,
        help="Path to a collect_domain_info.py TSV (the input to classify)",
    )
    p.add_argument(
        "--map-out",
        default="/tmp/additions.csv",
        help="Output CSV for map additions (domain,name,type). Default: %(default)s",
    )
    p.add_argument(
        "--ku-out",
        default="/tmp/ku_additions.txt",
        help="Output text file for known-unknown additions. Default: %(default)s",
    )
    p.add_argument(
        "--mmdb",
        default=DEFAULT_MMDB,
        help="Path to ipinfo_lite.mmdb. Default: bundled MMDB",
    )
    args = p.parse_args()

    adds, ku, stats = classify_tsv(args.input, args.mmdb)

    with open(args.map_out, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, lineterminator="\r\n")
        for r in adds:
            w.writerow(r)
    with open(args.ku_out, "w", encoding="utf-8") as f:
        for d in sorted(set(ku)):
            f.write(d + "\n")

    print(
        f"auto: {stats['auto']}, hand: {stats['hand']}, "
        f"ku: {stats['ku']} (unique: {len(set(ku))})",
        file=sys.stderr,
    )
    print(f"  map adds -> {args.map_out}")
    print(f"  ku adds  -> {args.ku_out}")


if __name__ == "__main__":
    main()


if __name__ == "__main__":
    main()
