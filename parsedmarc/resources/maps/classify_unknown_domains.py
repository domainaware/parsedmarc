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
defined for `base_reverse_dns_map.csv`'s `type` column). Multilingual
keyword coverage:

- **Top-volume detectors** (Healthcare, Travel, Government, Retail, Finance,
  ISP, Web Host, Manufacturing, Logistics, Real Estate, Automotive, Legal,
  Agriculture): concept-translation parity across ~30 languages with
  multiple synonyms per language.
- **Smaller detectors** (Photography, Sports, MSSP, Conglomerate, Search
  Engine, Social Media, Defense, IaaS/PaaS/SaaS, Beauty, Print, Publishing,
  Religion, Science, Event Planning, Staffing, Email Security, Email
  Provider, Marketing, Construction, Industrial, Utilities, Energy,
  Government Media, Physical Security, News, Nonprofit, Entertainment,
  Technology, Consulting): ~10–20 languages with 1–3 keywords each.

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
    r"penyedia layanan internet"
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
    # Spanish
    r"hospedaje (?:web|de )|alojamiento web|"
    # Portuguese
    r"hospedagem|"
    # French
    r"hébergement|webhébergement|"
    # German
    r"webhoster|rechenzentrum|"
    # Russian
    r"хостинг|центр обработки данных|"
    # Polish
    r"hosting stron|centrum danych|"
    # Estonian
    r"veebimajutus|"
    # Indonesian
    r"penyedia web hosting|"
    # Turkish
    r"web hosting şirketi|veri merkezi|"
    # Chinese
    r"虚拟主机|虛擬主機|主机服务|主機服務|数据中心|數據中心|"
    # Japanese
    r"レンタルサーバー|ホスティング|データセンター|"
    # Korean
    r"호스팅|데이터 센터|"
    # Arabic
    r"استضافة المواقع|مركز بيانات"
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
    r"มหาวิทยาลัย|โรงเรียน"
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
    r"regering|departement"
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
    r"medical practice|nursing home|surgical center|"
    r"diagnostic center|outpatient clinic|emergency room|"
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
    r"rumah sakit|klinik|apotek"
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
    r"reta vendejo"
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
    # Spanish
    r"fabricación|fabricante|fábrica|empresa manufacturera|manufacturera|"
    # Portuguese
    r"fabricação|fábrica|fabricante|"
    # French
    r"fabricant|usine|industrie manufacturière|"
    # Italian
    r"fabbricazione|costruttore|stabilimento produttivo|manufactura|"
    # German
    r"hersteller|fabrik|produktionsstätte|industriebetrieb|"
    # Dutch
    r"fabrikant|productiebedrijf|"
    # Polish
    r"producent|wytwórca|fabryka|"
    # Czech
    r"výrobce|závod|továrna|"
    # Slovak
    r"výrobca|továreň|"
    # Russian
    r"производитель|завод|фабрика|"
    # Ukrainian
    r"виробник|завод|фабрика|"
    # Bulgarian
    r"производител|фабрика|завод|"
    # Romanian
    r"producător|fabrică|"
    # Hungarian
    r"gyártó|gyár|"
    # Greek
    r"κατασκευαστής|βιομηχανία|εργοστάσιο|"
    # Turkish
    r"üretici|imalatçı|fabrika|"
    # Albanian
    r"prodhues|fabrikë|"
    # Croatian / Serbian / Bosnian
    r"proizvođač|fabrika|tvornica|"
    # Slovenian
    r"proizvajalec|tovarna|"
    # Estonian
    r"tootja|tehas|"
    # Latvian
    r"ražotājs|rūpnīca|"
    # Lithuanian
    r"gamintojas|gamykla|"
    # Finnish
    r"valmistaja|tehdas|"
    # Swedish
    r"tillverkare|fabrik|"
    # Norwegian
    r"produsent|fabrikk|"
    # Danish
    r"producent|fabrik|"
    # Icelandic
    r"framleiðandi|verksmiðja|"
    # Persian
    r"تولید کننده|کارخانه|"
    # Urdu
    r"تیار کنندہ|"
    # Arabic
    r"شركة تصنيع|مصنع|الصناعة التحويلية|"
    # Hebrew
    r"יצרן|מפעל|"
    # Hindi
    r"निर्माता|कारखाना|उत्पादन|"
    # Bengali
    r"প্রস্তুতকারক|কারখানা|"
    # Tamil
    r"தயாரிப்பாளர்|தொழிற்சாலை|"
    # Telugu
    r"తయారీదారు|"
    # Marathi
    r"उत्पादक|कारखाना|"
    # Chinese (Simplified and Traditional)
    r"制造商|製造商|工厂|工廠|生产厂|生產廠|生产商|生產商|"
    # Japanese
    r"製造業者|工場|"
    # Korean
    r"제조업체|제조사|공장|"
    # Vietnamese
    r"nhà sản xuất|nhà máy|"
    # Thai
    r"ผู้ผลิต|โรงงาน|"
    # Indonesian
    r"produsen|pabrik|"
    # Malay
    r"pengeluar|kilang|"
    # Filipino (Tagalog)
    r"tagagawa|pabrika|"
    # Swahili
    r"mtengenezaji|kiwanda|"
    # Catalan
    r"fabricant|fàbrica|"
    # Galician
    r"fabricante|fábrica|"
    # Welsh
    r"gwneuthurwr|ffatri|"
    # Irish
    r"déantóir|monarcha|"
    # Afrikaans
    r"vervaardiger|fabriek"
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
    r"hotel|biro perjalanan|maskapai penerbangan"
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
    # Spanish
    r"restaurante|panadería|alimentación|alimentos|"
    # Portuguese
    r"padaria|alimentação|alimentar|"
    # French
    r"patisserie|boulangerie|alimentaire|"
    # Italian
    r"ristorante|panetteria|"
    # German
    r"lebensmittel|nahrungsmittel|getränkehersteller|"
    # Russian
    r"производство продуктов питания|пищевая промышленность|"
    # Polish
    r"przemysł spożywczy|"
    # Turkish
    r"restoran|"
    # Greek
    r"εστιατόριο|"
    # Chinese
    r"食品|食物|餐厅|餐廳|"
    # Korean
    r"식품|음식|"
    # Japanese
    r"レストラン|食品メーカー|"
    r"레스토랑|"
    # Arabic
    r"المطعم|إنتاج الأغذية|صناعة الغذاء|"
    # Hebrew
    r"מסעדה|"
    # Vietnamese
    r"nhà hàng|"
    # Thai
    r"ร้านอาหาร"
    r")\b"
)

# Legal — law firms, legal services
LEGAL_RE = re.compile(
    r"(?i)\b("
    # English
    r"law firm|law offices?|attorneys at law|attorney at law|"
    r"legal services|legal counsel|legal advisors|"
    r"corporate law|tax law|family law|"
    # Spanish
    r"abogados|despacho de abogados|bufete de abogados|"
    # Portuguese
    r"escritório de advocacia|advogados|"
    # French
    r"avocats|cabinet d'avocats|cabinet juridique|"
    # Italian
    r"avvocati|studio legale|"
    # German
    r"rechtsanwälte|anwaltskanzlei|kanzlei|"
    # Dutch
    r"advocatenkantoor|"
    # Polish
    r"kancelaria prawna|adwokaci|"
    # Czech
    r"advokátní kancelář|právník|"
    # Slovak
    r"advokátska kancelária|"
    # Russian
    r"юридическая фирма|адвокатское бюро|адвокаты|"
    # Ukrainian
    r"юридична фірма|адвокатське бюро|"
    # Bulgarian
    r"адвокатска кантора|"
    # Romanian
    r"cabinet de avocatură|"
    # Hungarian
    r"ügyvédi iroda|"
    # Greek
    r"δικηγορικό γραφείο|"
    # Turkish
    r"hukuk bürosu|avukatlık|"
    # Albanian
    r"zyrë avokatie|"
    # Croatian / Serbian / Bosnian
    r"advokatska kancelarija|odvjetnički ured|"
    # Slovenian
    r"odvetniška pisarna|"
    # Estonian
    r"advokaadibüroo|"
    # Latvian
    r"advokātu birojs|"
    # Lithuanian
    r"advokatų kontora|"
    # Finnish
    r"asianajotoimisto|"
    # Swedish
    r"advokatbyrå|"
    # Norwegian
    r"advokatfirma|"
    # Danish
    r"advokatfirma|"
    # Icelandic
    r"lögmannsstofa|"
    # Persian
    r"شرکت حقوقی|"
    # Urdu
    r"وکالت|"
    # Arabic
    r"مكتب محاماة|"
    # Hebrew
    r"משרד עורכי דין|"
    # Hindi
    r"विधि फर्म|"
    # Bengali
    r"আইনি সংস্থা|"
    # Tamil
    r"வழக்கறிஞர் அலுவலகம்|"
    # Chinese (Simplified and Traditional)
    r"律师事务所|律師事務所|法律事务所|"
    # Japanese
    r"法律事務所|"
    # Korean
    r"법률사무소|로펌|"
    # Vietnamese
    r"công ty luật|"
    # Thai
    r"สำนักงานกฎหมาย|"
    # Indonesian
    r"firma hukum|"
    # Malay
    r"firma guaman|"
    # Filipino (Tagalog)
    r"opisina ng abogado|"
    # Swahili
    r"kampuni ya sheria|"
    # Catalan
    r"despatx d'advocats|"
    # Galician
    r"despacho de avogados|"
    # Welsh
    r"cwmni cyfreithiol|"
    # Afrikaans
    r"prokureursfirma"
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
    r"shopping mall management|business center management|"
    r"coworking|co-working|"
    # Spanish
    r"inmobiliaria|bienes raíces|gestión inmobiliaria|"
    # Portuguese
    r"imobiliária|imóveis|gestão imobiliária|"
    # French
    r"immobilier|agence immobilière|gestion immobilière|"
    # Italian
    r"agenzia immobiliare|gestione immobiliare|immobiliare|"
    # German
    r"immobilien|maklerbüro|immobilienverwaltung|"
    # Dutch
    r"makelaardij|vastgoed|"
    # Polish
    r"nieruchomości|biuro nieruchomości|zarządzanie nieruchomościami|"
    # Czech
    r"realitní kancelář|nemovitosti|"
    # Slovak
    r"realitná kancelária|"
    # Russian
    r"недвижимость|агентство недвижимости|"
    r"управление и эксплуатация (?:бизнес-центров|торговых центров)|"
    # Ukrainian
    r"нерухомість|агентство нерухомості|"
    # Bulgarian
    r"имоти|агенция за недвижими имоти|"
    # Romanian
    r"agenție imobiliară|imobiliare|"
    # Hungarian
    r"ingatlaniroda|ingatlanügynökség|"
    # Greek
    r"κτηματομεσιτικό γραφείο|ακίνητα|"
    # Turkish
    r"emlak ofisi|gayrimenkul|"
    # Albanian
    r"agjenci patundshmërish|"
    # Croatian / Serbian / Bosnian
    r"agencija za nekretnine|nekretnine|"
    # Slovenian
    r"nepremičninska agencija|"
    # Estonian
    r"kinnisvarabüroo|"
    # Latvian
    r"nekustamā īpašuma birojs|"
    # Lithuanian
    r"nekilnojamojo turto agentūra|"
    # Finnish
    r"kiinteistönvälitys|"
    # Swedish
    r"fastighetsmäklare|"
    # Norwegian
    r"eiendomsmegler|"
    # Danish
    r"ejendomsmægler|"
    # Icelandic
    r"fasteignasala|"
    # Persian
    r"املاک|دفتر مشاور املاک|"
    # Urdu
    r"رئیل اسٹیٹ|"
    # Arabic
    r"عقارات|"
    # Hebrew
    r"נדל\"ן|"
    # Hindi
    r"रियल एस्टेट|संपत्ति|"
    # Bengali
    r"রিয়েল এস্টেট|"
    # Tamil
    r"ரியல் எஸ்டேட்|"
    # Chinese (Simplified and Traditional)
    r"房地产|不动产|房地產|不動產|物业管理|物業管理|"
    # Japanese
    r"不動産|"
    # Korean
    r"부동산|"
    # Vietnamese
    r"bất động sản|"
    # Thai
    r"อสังหาริมทรัพย์|"
    # Indonesian
    r"properti|real estat|"
    # Malay
    r"hartanah|"
    # Filipino (Tagalog)
    r"real estate|"
    # Catalan
    r"immobiliària|"
    # Galician
    r"inmobiliaria|"
    # Afrikaans
    r"eiendomsagent"
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
    r"versekeringsmaatskappy|bank"
    r")\b"
)

# Automotive — dealers, auto manufacturers, auto parts
AUTOMOTIVE_RE = re.compile(
    r"(?i)\b("
    # English
    r"car dealer|auto dealer|auto dealership|"
    r"dealership for|car dealership|"
    r"auto parts|automotive parts|automotive supplier|"
    r"car rental|auto rental|car repair shop|"
    r"new and used cars|new & used cars|"
    # Spanish
    r"concesionario|alquiler de coches|"
    # Portuguese
    r"concessionária|aluguel de carros|"
    # French
    r"concessionnaire automobile|garage automobile|location de voiture|"
    # Italian
    r"concessionaria auto|"
    # German
    r"autohaus|fahrzeughändler|kfz[- ]?werkstatt|"
    # Dutch
    r"autoverhuur|autodealer|"
    # Polish
    r"salon samochodowy|wypożyczalnia samochodów|"
    # Czech
    r"autosalon|prodejce automobilů|"
    # Slovak
    r"predajca automobilov|"
    # Russian
    r"автосалон|автодилер|автоцентр|прокат автомобилей|"
    # Ukrainian
    r"автосалон|прокат автомобілів|"
    # Bulgarian
    r"автокъща|"
    # Romanian
    r"dealer auto|"
    # Hungarian
    r"autókereskedő|"
    # Greek
    r"αντιπροσωπεία αυτοκινήτων|"
    # Turkish
    r"otomobil bayisi|"
    # Croatian / Serbian / Bosnian
    r"prodaja automobila|"
    # Slovenian
    r"prodaja vozil|"
    # Estonian
    r"autode müük|"
    # Latvian
    r"automašīnu tirdzniecība|"
    # Lithuanian
    r"automobilių salonas|"
    # Finnish
    r"autokauppa|"
    # Swedish
    r"bilförsäljare|"
    # Norwegian
    r"bilforhandler|"
    # Danish
    r"bilforhandler|"
    # Icelandic
    r"bílasala|"
    # Persian
    r"نمایندگی خودرو|"
    # Arabic
    r"وكالة سيارات|"
    # Hebrew
    r"סוכנות רכב|"
    # Hindi
    r"कार डीलर|"
    # Chinese (Simplified and Traditional)
    r"汽车经销商|汽車經銷商|汽车租赁|汽車租賃|"
    # Japanese
    r"自動車ディーラー|"
    # Korean
    r"자동차 대리점|자동차 렌트|"
    # Vietnamese
    r"đại lý ô tô|"
    # Thai
    r"ตัวแทนจำหน่ายรถ|"
    # Indonesian
    r"dealer mobil|"
    # Malay
    r"pengedar kereta|"
    # Catalan
    r"concessionari de cotxes"
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
    # Portuguese
    r"casa de produção|estúdio de gravação|"
    # Italian
    r"casa di produzione|"
    # French
    r"production cinéma|production audiovisuelle|"
    # German
    r"filmproduktion|musikverlag|"
    # Russian
    r"кино студия|кинокомпания|музыкальный лейбл|"
    # Polish
    r"wytwórnia filmowa|wytwórnia muzyczna|"
    # Turkish
    r"film yapım şirketi|"
    # Chinese
    r"电影制作|电影公司|電影製作|電影公司|"
    r"游戏开发|遊戲開發|"
    # Korean
    r"영화 제작|게임 개발|"
    # Japanese
    r"映画制作|ゲーム開発|アニメ制作"
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
    # Portuguese
    r"segurança de e?mail|"
    # French
    r"sécurité des e?mails|"
    # German
    r"e?mail[- ]?sicherheit|"
    # Russian
    r"защита электронной почты|"
    # Chinese
    r"电子邮件安全|電子郵件安全|"
    # Japanese
    r"メールセキュリティ|"
    # Korean
    r"이메일 보안"
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
    r"agencia de marketing|"
    # Portuguese
    r"agência de marketing|"
    # French
    r"agence de marketing|"
    # German
    r"marketingagentur|werbeagentur|"
    # Russian
    r"маркетинговое агентство|"
    # Chinese
    r"营销平台|營銷平台|广告公司|廣告公司|"
    # Japanese
    r"マーケティング会社|"
    # Korean
    r"마케팅 플랫폼"
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
    # Portuguese
    r"provedor de e?mail|hospedagem de e?mail|"
    # French
    r"fournisseur de messagerie|hébergement de messagerie|"
    # German
    r"e?mail[- ]?provider|e?mail[- ]?hosting|"
    # Russian
    r"почтовый провайдер|хостинг электронной почты"
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
    # Spanish
    r"agricultura|agroindustria|ganadería|"
    # Portuguese
    r"agronegócio|agropecuária|agricultura|"
    # French
    r"agriculture|agroalimentaire|exploitation agricole|"
    # Italian
    r"agricoltura|allevamento|"
    # German
    r"landwirtschaft|agrarwirtschaft|"
    # Dutch
    r"landbouw|"
    # Polish
    r"rolnictwo|"
    # Czech
    r"zemědělství|"
    # Slovak
    r"poľnohospodárstvo|"
    # Russian
    r"сельское хозяйство|агропромышленность|"
    # Ukrainian
    r"сільське господарство|"
    # Bulgarian
    r"земеделие|"
    # Romanian
    r"agricultură|"
    # Hungarian
    r"mezőgazdaság|"
    # Greek
    r"γεωργία|"
    # Turkish
    r"tarım|tarımsal işletme|"
    # Albanian
    r"bujqësi|"
    # Croatian / Serbian / Bosnian
    r"poljoprivreda|"
    # Slovenian
    r"kmetijstvo|"
    # Estonian
    r"põllumajandus|"
    # Latvian
    r"lauksaimniecība|"
    # Lithuanian
    r"žemės ūkis|"
    # Finnish
    r"maatalous|"
    # Swedish
    r"jordbruk|"
    # Norwegian
    r"landbruk|"
    # Danish
    r"landbrug|"
    # Icelandic
    r"landbúnaður|"
    # Persian
    r"کشاورزی|"
    # Arabic
    r"زراعة|"
    # Hebrew
    r"חקלאות|"
    # Hindi
    r"कृषि|"
    # Bengali
    r"কৃষি|"
    # Tamil
    r"விவசாயம்|"
    # Telugu
    r"వ్యవసాయం|"
    # Marathi
    r"शेती|"
    # Chinese (Simplified and Traditional)
    r"农业|農業|农业产业|農業產業|"
    # Japanese
    r"農業|"
    # Korean
    r"농업|"
    # Vietnamese
    r"nông nghiệp|"
    # Thai
    r"เกษตรกรรม|"
    # Indonesian
    r"pertanian|"
    # Malay
    r"pertanian|"
    # Filipino (Tagalog)
    r"agrikultura|"
    # Swahili
    r"kilimo|"
    # Catalan
    r"agricultura|"
    # Welsh
    r"amaethyddiaeth|"
    # Afrikaans
    r"landbou"
    r")\b"
)

BEAUTY_RE = re.compile(
    r"(?i)\b("
    # English
    r"beauty salon|beauty products|cosmetics|cosmetic products|"
    r"skincare|skin care|hair salon|"
    r"makeup|fragrance|perfume|"
    # Spanish
    r"belleza|salón de belleza|productos de belleza|"
    # Portuguese
    r"beleza|salão de beleza|"
    # French
    r"beauté|salon de beauté|cosmétiques|"
    # German
    r"kosmetik|schönheitssalon|friseursalon|"
    # Russian
    r"косметика|салон красоты|"
    # Chinese
    r"美容|化妆品|化妝品|"
    # Japanese
    r"美容|化粧品|"
    # Korean
    r"미용|화장품"
    r")\b"
)

CONSTRUCTION_RE = re.compile(
    r"(?i)\b("
    # English
    r"construction company|general contractor|"
    r"building contractor|construction services|"
    r"construction firm|civil engineering|"
    r"home builder|residential construction|"
    # Spanish
    r"empresa de construcción|"
    # Portuguese
    r"construtora|"
    # French
    r"entreprise de construction|"
    # Italian
    r"impresa di costruzioni|"
    # German
    r"baufirma|bauunternehmen|"
    # Russian
    r"строительная компания|"
    # Polish
    r"firma budowlana|"
    # Turkish
    r"inşaat şirketi|"
    # Chinese
    r"建筑公司|建築公司|建筑工程|建築工程|"
    # Japanese
    r"建設会社|"
    # Korean
    r"건설회사|"
    # Arabic
    r"شركة البناء"
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
    # Portuguese
    r"consultoria|"
    # French
    r"cabinet de conseil|société de conseil|"
    # Italian
    r"società di consulenza|"
    # German
    r"unternehmensberatung|beratungsunternehmen|"
    # Russian
    r"консалтинг|консалтинговая компания|"
    # Polish
    r"firma konsultingowa|doradztwo|"
    # Turkish
    r"danışmanlık şirketi|"
    # Chinese
    r"咨询公司|諮詢公司|"
    # Japanese
    r"コンサルティング会社|"
    # Korean
    r"컨설팅 회사"
    r")\b"
)

DEFENSE_RE = re.compile(
    r"(?i)\b("
    # English
    r"defense contractor|defence contractor|"
    r"defense industry|aerospace and defense|"
    r"military equipment|weapons manufacturer|"
    r"military aerospace|defense electronics|"
    # Spanish
    r"industria de defensa|"
    # Portuguese
    r"indústria de defesa|"
    # French
    r"industrie de défense|"
    # German
    r"verteidigungsindustrie|rüstungsindustrie|"
    # Russian
    r"оборонная промышленность|оборонный комплекс|"
    # Chinese
    r"国防工业|國防工業|军工|軍工|"
    # Japanese
    r"防衛産業|"
    # Korean
    r"방위산업"
    r")\b"
)

EVENT_PLANNING_RE = re.compile(
    r"(?i)\b("
    # English
    r"event planning|event management|"
    r"event production|event services|"
    r"wedding planning|conference planning|"
    r"corporate events|trade show|"
    # Spanish
    r"organización de eventos|"
    # Portuguese
    r"organização de eventos|"
    # French
    r"organisation d'événements|"
    # Italian
    r"organizzazione di eventi|"
    # German
    r"eventmanagement|veranstaltungsorganisation|"
    # Russian
    r"организация мероприятий|"
    # Chinese
    r"活动策划|活動策劃|"
    # Japanese
    r"イベント企画|"
    # Korean
    r"이벤트 기획"
    r")\b"
)

LOGISTICS_RE = re.compile(
    r"(?i)\b("
    # English
    r"logistics|freight forwarding|freight forwarder|"
    r"shipping and logistics|supply chain|"
    r"customs brokerage|express shipping|"
    r"trucking|cargo services|warehousing|"
    # Spanish
    r"logística|transporte de mercancías|"
    # Portuguese
    r"transporte de cargas|"
    # French
    r"logistique|transitaire|"
    # Italian
    r"logistica|"
    # German
    r"logistikunternehmen|spedition|"
    # Dutch
    r"logistiek|expediteur|"
    # Polish
    r"firma logistyczna|spedycja|"
    # Czech
    r"logistická společnost|spediční společnost|"
    # Slovak
    r"logistická spoločnosť|"
    # Russian
    r"логистика|логистическая компания|"
    # Ukrainian
    r"логістика|"
    # Bulgarian
    r"логистика|"
    # Romanian
    r"logistică|expediție|"
    # Hungarian
    r"logisztika|szállítmányozás|"
    # Greek
    r"εφοδιαστική|μεταφορική εταιρεία|"
    # Turkish
    r"lojistik şirketi|kargo şirketi|"
    # Albanian
    r"logjistikë|"
    # Croatian / Serbian / Bosnian
    r"logistika|špedicija|"
    # Slovenian
    r"logistika|"
    # Estonian
    r"logistika|"
    # Latvian
    r"loģistika|"
    # Lithuanian
    r"logistika|"
    # Finnish
    r"logistiikka|"
    # Swedish
    r"logistik|"
    # Norwegian
    r"logistikk|"
    # Danish
    r"logistik|"
    # Icelandic
    r"flutningar|"
    # Persian
    r"لجستیک|"
    # Arabic
    r"الخدمات اللوجستية|شركة شحن|"
    # Hebrew
    r"לוגיסטיקה|"
    # Hindi
    r"रसद|लॉजिस्टिक्स|"
    # Bengali
    r"লজিস্টিকস|"
    # Tamil
    r"தளவாட சேவை|"
    # Chinese (Simplified and Traditional)
    r"物流公司|物流服务|物流服務|货运代理|貨運代理|"
    # Japanese
    r"物流|"
    # Korean
    r"물류 회사|"
    # Vietnamese
    r"công ty hậu cần|công ty logistics|"
    # Thai
    r"บริษัทโลจิสติกส์|"
    # Indonesian
    r"perusahaan logistik|"
    # Malay
    r"syarikat logistik|"
    # Filipino (Tagalog)
    r"kumpanya ng lohistika|"
    # Catalan
    r"logística|"
    # Galician
    r"loxística|"
    # Welsh
    r"logisteg|"
    # Swahili
    r"shughuli za usafirishaji|"
    # Afrikaans
    r"logistiek"
    r")\b"
)

MSSP_RE = re.compile(
    r"(?i)\b("
    # English
    r"mssp\b|managed security services|"
    r"managed security service provider|"
    r"managed detection and response|mdr\b|"
    r"managed cybersecurity|security operations center|soc\b|"
    # Spanish
    r"servicios de seguridad gestionados|"
    # Portuguese
    r"serviços de segurança gerenciados|"
    # French
    r"services de sécurité gérés|"
    # German
    r"managed security|cyber security dienst"
    r")\b"
)

NEWS_RE = re.compile(
    r"(?i)\b("
    # English
    r"news organization|newspaper|news network|news publisher|"
    r"newsroom|news media|breaking news|"
    r"news outlet|news website|"
    # Spanish
    r"diario|periódico|noticias|"
    # Portuguese
    r"jornal|"
    # French
    r"journal|quotidien|"
    # Italian
    r"giornale|quotidiano|"
    # German
    r"zeitung|nachrichtenmedium|"
    # Russian
    r"редакция|информационное агентство|газета|"
    # Polish
    r"gazeta|portal informacyjny|"
    # Turkish
    r"gazete|haber ajansı|"
    # Chinese
    r"新闻|新聞|新闻网站|新聞網站|报纸|報紙|"
    # Japanese
    r"新聞社|"
    # Korean
    r"신문사"
    r")\b"
)

NONPROFIT_RE = re.compile(
    r"(?i)\b("
    # English
    r"nonprofit|non[- ]profit|not[- ]for[- ]profit|"
    r"charity|charitable organization|charitable foundation|"
    r"501\(c\)\(3\)|registered charity|"
    # Spanish
    r"organización sin fines de lucro|"
    # Portuguese
    r"organização sem fins lucrativos|"
    # French
    r"organisation à but non lucratif|"
    # Italian
    r"organizzazione senza scopo di lucro|"
    # German
    r"gemeinnützige|nichtregierungsorganisation|"
    # Russian
    r"некоммерческая организация|"
    # Polish
    r"organizacja non[- ]profit|"
    # Chinese
    r"非营利组织|非營利組織|"
    # Japanese
    r"非営利団体|"
    # Korean
    r"비영리 단체"
    r")\b"
)

PHOTOGRAPHY_RE = re.compile(
    r"(?i)\b("
    # English
    r"photography studio|photo studio|"
    r"professional photographer|wedding photographer|"
    r"commercial photography|stock photography|"
    # Spanish
    r"estudio fotográfico|"
    # Portuguese
    r"estúdio fotográfico|"
    # French
    r"studio photo|studio de photographie|"
    # German
    r"fotostudio|"
    # Russian
    r"фотостудия|"
    # Chinese
    r"摄影工作室|攝影工作室|"
    # Japanese
    r"写真スタジオ|"
    # Korean
    r"사진 스튜디오"
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
    # Portuguese
    r"empresa de segurança|"
    # French
    r"sécurité privée|société de gardiennage|"
    # German
    r"sicherheitsdienst|wachdienst|"
    # Russian
    r"охранная компания|охранное предприятие|"
    # Polish
    r"firma ochroniarska|"
    # Turkish
    r"güvenlik şirketi|"
    # Chinese
    r"安保公司|保安公司|"
    # Japanese
    r"警備会社|"
    # Korean
    r"보안 회사"
    r")\b"
)

PRINT_RE = re.compile(
    r"(?i)\b("
    # English
    r"printing company|printing services|"
    r"commercial printing|print shop|print provider|"
    # Spanish
    r"imprenta|impresor|"
    # Portuguese
    r"impressão|gráfica|"
    # French
    r"imprimerie|"
    # German
    r"druckerei|"
    # Russian
    r"типография|"
    # Polish
    r"drukarnia|"
    # Turkish
    r"matbaa|"
    # Chinese
    r"印刷公司|印刷厂|印刷廠|"
    # Japanese
    r"印刷会社|"
    # Korean
    r"인쇄소"
    r")\b"
)

PUBLISHING_RE = re.compile(
    r"(?i)\b("
    # English
    r"publishing house|book publisher|"
    r"academic publisher|magazine publisher|"
    r"editorial group|publishing group|"
    # Spanish
    r"editorial|casa editorial|"
    # Portuguese
    r"editora|"
    # French
    r"maison d'édition|"
    # Italian
    r"casa editrice|"
    # German
    r"verlag|verlagshaus|"
    # Russian
    r"издательство|"
    # Polish
    r"wydawnictwo|"
    # Chinese
    r"出版社|出版公司|"
    # Japanese
    r"出版社|"
    # Korean
    r"출판사"
    r")\b"
)

RELIGION_RE = re.compile(
    r"(?i)\b("
    # English
    r"church|cathedral|parish|diocese|"
    r"mosque|synagogue|temple|monastery|"
    r"religious organization|religious community|"
    r"faith community|ministries|"
    # Spanish
    r"iglesia|parroquia|"
    # Portuguese
    r"igreja|paróquia|"
    # French
    r"église|paroisse|"
    # Italian
    r"chiesa|parrocchia|"
    # German
    r"kirche|gemeinde|"
    # Russian
    r"церковь|приход|"
    # Polish
    r"kościół|parafia|"
    # Turkish
    r"camii|kilise|"
    # Chinese
    r"教会|教會|清真寺|"
    # Japanese
    r"教会|寺院|神社|"
    # Korean
    r"교회|성당|사찰|"
    # Arabic
    r"مسجد|كنيسة|"
    # Hebrew
    r"בית כנסת|"
    # Hindi
    r"मंदिर|"
    # Thai
    r"วัด"
    r")\b"
)

SCIENCE_RE = re.compile(
    r"(?i)\b("
    # English
    r"research institute|research laboratory|research center|"
    r"scientific research|laboratory of\b|"
    r"national laboratory|observatory|"
    # Spanish
    r"instituto de investigación|laboratorio nacional|"
    # Portuguese
    r"instituto de pesquisa|"
    # French
    r"institut de recherche|laboratoire national|"
    # Italian
    r"istituto di ricerca|"
    # German
    r"forschungsinstitut|forschungslabor|"
    # Russian
    r"научно-исследовательский институт|научный институт|"
    # Polish
    r"instytut badawczy|"
    # Chinese
    r"研究所|研究中心|实验室|實驗室|"
    # Japanese
    r"研究所|研究機関|"
    # Korean
    r"연구소"
    r")\b"
)

SEARCH_ENGINE_RE = re.compile(
    r"(?i)\b("
    # English
    r"search engine|web search|"
    # Spanish
    r"buscador web|motor de búsqueda|"
    # Portuguese
    r"motor de busca|"
    # French
    r"moteur de recherche|"
    # German
    r"suchmaschine|"
    # Russian
    r"поисковая система|"
    # Chinese
    r"搜索引擎|搜尋引擎|"
    # Japanese
    r"検索エンジン|"
    # Korean
    r"검색 엔진"
    r")\b"
)

SOCIAL_MEDIA_RE = re.compile(
    r"(?i)\b("
    # English
    r"social media platform|social network site|social networking|"
    r"online community platform|"
    # Spanish
    r"red social|plataforma de redes sociales|"
    # Portuguese
    r"rede social|"
    # French
    r"réseau social|"
    # German
    r"soziales netzwerk|"
    # Russian
    r"социальная сеть|"
    # Chinese
    r"社交媒体|社交媒體|"
    # Japanese
    r"ソーシャルメディア|"
    # Korean
    r"소셜 미디어"
    r")\b"
)

SPORTS_RE = re.compile(
    r"(?i)\b("
    # English
    r"sports team|football club|soccer club|"
    r"baseball team|basketball team|hockey team|"
    r"sports league|athletic association|"
    r"sports federation|sporting goods|"
    # Spanish
    r"club deportivo|equipo de fútbol|"
    # Portuguese
    r"clube de futebol|clube esportivo|"
    # French
    r"club sportif|club de football|"
    # Italian
    r"squadra di calcio|club sportivo|"
    # German
    r"sportverein|fußballverein|"
    # Russian
    r"спортивный клуб|футбольный клуб|"
    # Polish
    r"klub piłkarski|klub sportowy|"
    # Turkish
    r"spor kulübü|"
    # Chinese
    r"体育俱乐部|足球俱乐部|體育俱樂部|足球俱樂部|"
    # Japanese
    r"スポーツクラブ|サッカークラブ|"
    # Korean
    r"스포츠 클럽"
    r")\b"
)

STAFFING_RE = re.compile(
    r"(?i)\b("
    # English
    r"staffing agency|staffing services|"
    r"recruitment agency|recruiting firm|"
    r"talent acquisition|placement agency|"
    r"temp agency|temporary staffing|"
    # Spanish
    r"agencia de empleo|empresa de selección|"
    # Portuguese
    r"agência de empregos|"
    # French
    r"agence de recrutement|cabinet de recrutement|"
    # Italian
    r"agenzia per il lavoro|"
    # German
    r"personalvermittlung|zeitarbeit|"
    # Russian
    r"кадровое агентство|"
    # Polish
    r"agencja pracy|"
    # Turkish
    r"insan kaynakları şirketi|"
    # Chinese
    r"人力资源公司|人力資源公司|招聘公司|"
    # Japanese
    r"人材紹介|人材派遣|"
    # Korean
    r"인재 채용 회사"
    r")\b"
)

TECHNOLOGY_RE = re.compile(
    r"(?i)\b("
    # English
    r"technology consulting|tech consulting|"
    r"software development|software company|"
    r"app development|mobile app development|"
    r"systems integrator|systems integration|"
    # Spanish
    r"empresa de tecnología|desarrollo de software|"
    # Portuguese
    r"empresa de tecnologia|desenvolvimento de software|"
    # French
    r"entreprise de technologie|développement de logiciels|"
    # Italian
    r"azienda tecnologica|"
    # German
    r"technologieunternehmen|softwareentwicklung|"
    # Russian
    r"технологическая компания|разработка программного обеспечения|"
    # Polish
    r"firma technologiczna|"
    # Turkish
    r"teknoloji şirketi|"
    # Chinese
    r"科技公司|科技服务|科技服務|软件开发|軟體開發|"
    # Japanese
    r"テクノロジー企業|ソフトウェア開発|"
    # Korean
    r"기술 회사|소프트웨어 개발"
    r")\b"
)

UTILITIES_RE = re.compile(
    r"(?i)\b("
    # English
    r"electric utility|electricity provider|electric power|"
    r"power company|gas utility|natural gas utility|"
    r"water utility|water authority|public utility|"
    # Spanish
    r"compañía eléctrica|cooperativa de electricidad|"
    # Portuguese
    r"companhia elétrica|"
    # French
    r"compagnie d'électricité|"
    # Italian
    r"società elettrica|"
    # German
    r"energieversorger|stromversorger|"
    # Russian
    r"электроэнергетическая компания|энергоснабжающая организация|"
    # Polish
    r"przedsiębiorstwo energetyczne|"
    # Turkish
    r"elektrik dağıtım şirketi|"
    # Chinese
    r"电力公司|電力公司|供水公司|燃气公司|燃氣公司|"
    # Japanese
    r"電力会社|ガス会社|"
    # Korean
    r"전력 회사|가스 회사"
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
    # Spanish
    r"empresa de energía|servicios energéticos|"
    # Portuguese
    r"empresa de energia|"
    # French
    r"entreprise énergétique|services énergétiques|"
    # Italian
    r"azienda energetica|"
    # German
    r"energieunternehmen|energiedienstleister|"
    # Russian
    r"энергетическая компания|"
    # Polish
    r"firma energetyczna|rozwiązania energetyczne|"
    # Turkish
    r"enerji şirketi|"
    # Chinese
    r"能源公司|能源服务|能源服務|"
    # Japanese
    r"エネルギー会社|"
    # Korean
    r"에너지 회사"
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
    # Portuguese
    r"emissora pública|"
    # French
    r"radiodiffuseur public|"
    # German
    r"öffentlich-rechtlicher rundfunk|"
    # Russian
    r"государственное СМИ|общественное вещание|"
    # Chinese
    r"国有媒体|國有媒體|国家广播|"
    # Japanese
    r"公共放送|"
    # Korean
    r"공영방송"
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
    # Spanish
    r"industria pesada|empresa minera|industria petroquímica|"
    # Portuguese
    r"indústria pesada|petroquímica|"
    # French
    r"industrie lourde|société minière|pétrochimie|"
    # Italian
    r"industria pesante|petrolchimica|"
    # German
    r"schwerindustrie|bergbauunternehmen|petrochemie|"
    # Russian
    r"тяжелая промышленность|горнодобывающая компания|нефтехимия|"
    # Polish
    r"przemysł ciężki|"
    # Turkish
    r"ağır sanayi|"
    # Chinese
    r"重工业|重工業|矿业公司|礦業公司|石化|"
    # Japanese
    r"重工業|鉱業|石油化学|"
    # Korean
    r"중공업|광업|석유화학"
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
    r"infraestructura como servicio|"
    # Portuguese
    r"infraestrutura como serviço|"
    # French
    r"infrastructure en tant que service|"
    # German
    r"infrastruktur als dienst|"
    # Russian
    r"инфраструктура как услуга|"
    # Chinese
    r"基础设施即服务|基礎設施即服務|"
    # Japanese
    r"インフラサービス|"
    # Korean
    r"인프라 서비스"
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
    # Portuguese
    r"plataforma como serviço|"
    # French
    r"plateforme en tant que service|"
    # German
    r"plattform als dienst|"
    # Russian
    r"платформа как услуга|"
    # Chinese
    r"平台即服务|平台即服務|"
    # Japanese
    r"プラットフォームサービス|"
    # Korean
    r"플랫폼 서비스"
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
    r"software como servicio|"
    # Portuguese
    r"software como serviço|"
    # French
    r"logiciel en tant que service|"
    # German
    r"software als dienst|"
    # Russian
    r"программное обеспечение как услуга|"
    # Chinese
    r"软件即服务|軟體即服務|"
    # Japanese
    r"ソフトウェアサービス|"
    # Korean
    r"소프트웨어 서비스"
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
    r"grupo empresarial diversificado|"
    # Portuguese
    r"conglomerado empresarial|"
    # French
    r"groupe diversifié|"
    # German
    r"mischkonzern|"
    # Russian
    r"конгломерат|"
    # Chinese
    r"多元化集团|多元化集團|"
    # Japanese
    r"複合企業|"
    # Korean
    r"복합 기업"
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
