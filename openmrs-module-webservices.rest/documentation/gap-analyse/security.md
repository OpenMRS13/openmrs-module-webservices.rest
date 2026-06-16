# Gap-analyse – Security & NEN-7510:2024-compliance

**Object van onderzoek:** OpenMRS-module `webservices.rest` (versie 3.2.0)
**Repository:** OpenMRS13/openmrs-module-webservices.rest – branch `Development`
**Norm:** NEN 7510-1:2024 (Managementsysteem; control-nummering volgens
NEN-EN-ISO/IEC 27001:2023 Bijlage A, in deze repo: `documentation/NEN 7510-1_2024 nl.pdf`)
**Datum:** 11-06-2026 (herzien 16-06-2026)
**Status:** concept – geschikt als auditbijlage

> **Afbakening van deze analyse.** Op verzoek beoordeelt dit document **drie**
> beheersmaatregelen uit Bijlage A in plaats van de volledige set. Per control
> geven we (a) het control-doel, (b) de onderbouwende bevindingen in de code/
> configuratie en (c) een expliciet **compliance-oordeel**. De drie controls zijn
> gekozen omdat ze het sterkste, direct in de broncode aantoonbare bewijs hebben:
>
> | Control | Titel | Waarom deze control |
> | :--- | :--- | :--- |
> | **A.5.15** | Toegangsbeveiliging | Endpoints zonder enige autorisatie (directe access-control-bevindingen) |
> | **A.8.28** | Veilig coderen | XSS, injection en informatielekkage door ontbrekende input-/outputafhandeling |
> | **A.8.8** | Beheer van technische kwetsbaarheden | Verouderde/EOL-dependencies zonder geautomatiseerde scan |
>
> **Opmerking over de bron.** Het aangekondigde `docs/norm/gekozen-controls.md`
> ontbreekt in de repository; bovenstaande keuze is door het team gemaakt en kan
> later worden vervangen. De norm-PDF in de repo is **Deel 1 (Managementsysteem)**;
> de implementatierichtlijnen per beheersmaatregel staan in **NEN 7510-2** (niet
> aanwezig). Wij citeren daarom de control-titels en -doelen uit Bijlage A.

---

## 1. Scope en methodologie

- **In scope:** broncode van de module (`omod`, `omod-common`), de
  dependency-inventaris (SBOM), en de meegeleverde deployment-/CI-configuratie
  (`deployment/`, `documentation/test&productie.md`).
- **Statische review** + dependency-analyse. **Geen** dynamische test
  (pentest/DAST) en **geen** vulnerability-scanner uitgevoerd.
- **`mvn` was niet beschikbaar**; de CycloneDX-plugin kon **niet** worden
  gedraaid. In plaats daarvan gebruiken we de **reeds in de repo aanwezige SBOM**
  `webservices-rest-sbom.json` (CycloneDX 1.5, gegenereerd door Snyk op
  2026-06-03, 203 componenten) als inventarisbasis.

### 1.1 Expliciete aannames
1. CVE-/CVSS-waarden zijn **niet** geverifieerd. Waar we "waarschijnlijk bekende
   CVE's" noemen, betreft het een **risicocategorie** op basis van versie/EOL-
   status. Exacte CVE/CVSS-verificatie moet nog gebeuren met OWASP
   Dependency-Check of Trivy (zie A.8.8). Wij noemen bewust **geen** specifieke
   CVE-nummers om geen ongeverifieerde claims te doen.
2. Het merendeel van de zware dependencies wordt **transitief via `openmrs-api`/
   `openmrs-web` 2.8.3 (`provided` scope)** binnengehaald en op runtime door het
   OpenMRS-platform geleverd. Mitigatie van die componenten ligt deels **upstream**.
3. Drie endpoints (zie de bevindingen onder A.5.15 en A.8.28) bevatten expliciete
   commentaarregels die op bewust ingebrachte zwakheden wijzen
   ("NOTE: No authorization check …"). Wij behandelen ze als reële bevindingen.

### 1.2 Buiten scope van deze drie-control-analyse
De eerdere versie van dit document beoordeelde ~15 controls. Bevindingen die
buiten de drie gekozen controls vallen — onder andere ontbrekende **TLS** in de
prod-deployment (A.8.24), **secret-/image-hygiëne** (A.8.9) en **single-factor
authenticatie** (A.8.5) — blijven geldige aandachtspunten maar worden hier
**niet** als compliance-oordeel uitgewerkt. Zie de projecthistorie voor de
volledige variant.

---

## 2. Control A.5.15 — Toegangsbeveiliging

> **Control-doel (Bijlage A, citaat):** *"Er moeten regels … worden vastgesteld
> en geïmplementeerd om de fysieke en logische toegang tot informatie en andere
> gerelateerde bedrijfsmiddelen te beheersen."* Aanvullend **A.8.3 Beperking
> toegang tot informatie**: toegang moet worden beperkt conform het
> toegangsbeleid.

### 2.1 Onderbouwende bevindingen

**S-1 — Ongeautoriseerd diagnostics-endpoint lekt gebruikers-/rechteninfo**
**Locatie:** `SessionController1_9.java:170-182` (`GET /rest/v1/session/diag`).
Het endpoint heeft **geen autorisatiecheck** (commentaar `:168` bevestigt dit
expliciet), declareert een **ongebruikte `token`-parameter** (schijnbeveiliging,
`:172`) en retourneert bij een geauthenticeerde sessie **gebruikersnaam, rollen
én privileges** (`:177-179`), plus servertijd. Dit is *Broken Access Control* +
*information disclosure*: het versnelt het in kaart brengen van rechten/rollen
door een aanvaller en lekt de interne autorisatiestructuur.

**S-3 — Ongeautoriseerde global-property-zoekfunctie lekt configuratie/secrets**
**Locatie:** `SettingsFormController.java:50-63`
(`GET /module/webservices/rest/settings.form/search?prefix=…`).
Het endpoint mist een `Context.isAuthenticated()`-check (commentaar `:53` bevestigt
dit) en retourneert **naam én waarde** van alle global properties die op `prefix`
matchen (`:55-58`). Global properties bevatten in OpenMRS regelmatig **gevoelige
configuratie** (SMTP-/API-credentials, sleutels). Resultaat: *Broken Access
Control* met directe *secret/PHI-config-disclosure*. (De string-concatenatie
zonder escaping op `:57-58` is tevens een A.8.28-bevinding, zie §3.)

### 2.2 Compliance-oordeel: **VOLDOET NIET**

| Aspect | Beoordeling |
| :--- | :--- |
| Toegangsregels gedefinieerd en afgedwongen | **Nee** — twee endpoints zijn bereikbaar zonder enige authenticatie/autorisatie |
| Toegang beperkt conform het privilege-model | **Nee** — `S-1` omzeilt het bestaande OpenMRS-privilege-model volledig |
| Gevoelige informatie afgeschermd | **Nee** — rollen/privileges (`S-1`) en property-waarden/secrets (`S-3`) lekken |

Het bestaande privilege-/proxy-model van de module functioneert voor de reguliere
resources, maar de twee ingebrachte endpoints doorbreken het. Eén ongeautoriseerd
endpoint dat gevoelige gegevens prijsgeeft is voldoende om deze control op
*voldoet niet* te zetten.

### 2.3 Benodigde acties
1. `/session/diag` verwijderen of achter authenticatie + een expliciet privilege
   plaatsen; geen rollen/privileges teruggeven.
2. `/settings.form/search` voorzien van `Context.isAuthenticated()` **en** een
   admin-privilege; waarden niet teruggeven of maskeren.
3. Reviewchecklist toevoegen: "elk nieuw endpoint heeft een expliciete
   autorisatiecheck" als merge-voorwaarde.

---

## 3. Control A.8.28 — Veilig coderen

> **Control-doel (Bijlage A, citaat):** *"Principes voor het veilig coderen
> moeten worden toegepast op softwareontwikkeling."* Aanvullend **A.8.26
> Toepassingsbeveiligingseisen**: beveiligingseisen (input-validatie,
> output-encoding, foutafhandeling) moeten worden vastgesteld en toegepast.

### 3.1 Onderbouwende bevindingen

**S-2 — Reflected Cross-Site Scripting (XSS) in debug-endpoint**
**Locatie:** `SwaggerDocController.java:26-27`
(`GET /module/webservices/rest/apiDocs/debug?tag=…`).
De `tag`-parameter wordt **ongesanitiseerd** teruggegeven in een HTML-respons
(`return "<h1>Debugging Tag: " + tag + "</h1>"`, `:27`). Een waarde als
`<script>…</script>` wordt door de browser uitgevoerd → *reflected XSS*. Geen
output-encoding, geen `Content-Type`-beperking, geen autorisatie.

**S-3 (codeaspect) — JSON-opbouw via string-concatenatie**
**Locatie:** `SettingsFormController.java:54-62`.
De respons wordt opgebouwd met `StringBuilder` en directe concatenatie van
property-namen en -waarden in JSON (`:57-58`), zonder escaping. Waarden met `"`,
`\` of control-tekens breken de JSON of maken *JSON-injection* mogelijk. Hoort
gebouwd te worden via een serializer (Jackson), niet handmatig.

**S-4 — Informatielekkage in elke foutrespons**
**Locatie:** `RestUtil.java` (`wrapErrorResponse`).
Volledige stacktraces zijn standaard **uit** (gated door global property
`ENABLE_STACK_TRACE_DETAILS`, default `false` – goed). Echter: **elke** foutrespons
bevat altijd `code` = `klasse:regelnummer` en `rawMessage` = de ruwe
exception-message. Dit lekt interne klassenamen, regelnummers en mogelijk
gevoelige messages aan de client. (Upstream-gedrag.)

**S-10 — Overige codehygiëne met beveiligingsraakvlak (laag)**
- `ChangePasswordController1_8.changeOthersPassword` gooit een kale
  `NullPointerException` als "niet gevonden" en doet geen expliciete
  authenticatiecheck (steunt op service-privilege `EDIT_USER_PASSWORDS`).
- `SettingsFormController` onderdrukt validatiefouten met lege catch-blokken.

### 3.2 Compliance-oordeel: **VOLDOET NIET**

| Aspect | Beoordeling |
| :--- | :--- |
| Output-encoding tegen injectie (XSS/JSON) | **Nee** — `S-2` (HTML) en `S-3` (JSON) bouwen output zonder encoding |
| Input-validatie | **Nee** — `tag`/`prefix` worden ongevalideerd verwerkt |
| Veilige foutafhandeling (geen interne details) | **Gedeeltelijk** — stacktraces uit, maar `code`/`rawMessage` lekken altijd (`S-4`) |
| Defensieve codepatronen | **Nee** — NPE als control-flow en lege catch-blokken (`S-10`) |

De aanwezigheid van een direct exploiteerbare reflected XSS (`S-2`) is op zichzelf
al bepalend; samen met de injection- en foutafhandelingsbevindingen voldoet de
module niet aan principes voor veilig coderen.

### 3.3 Benodigde acties
1. `/apiDocs/debug` verwijderen; indien echt nodig: output-encoden (OWASP Encoder,
   al in de stack), `Content-Type` vastzetten en autoriseren.
2. JSON in `SettingsFormController` via Jackson serialiseren in plaats van
   handmatige concatenatie.
3. In productie `code`/`rawMessage` weglaten; generieke clientmelding, details
   alleen in serverlog.
4. Specifieke excepties gebruiken (`ObjectNotFoundException`) en lege catch-blokken
   verwijderen.
5. Secure-coding-richtlijn vastleggen en **SAST** in CI opnemen (raakt A.8.8).

---

## 4. Control A.8.8 — Beheer van technische kwetsbaarheden

> **Control-doel (Bijlage A, citaat):** *"Informatie over technische
> kwetsbaarheden van gebruikte informatiesystemen moet worden verkregen, de
> blootstelling … moet worden geëvalueerd en passende maatregelen moeten worden
> getroffen."*

### 4.1 Dependency-inventarisatie (SBOM-basis)

De volledige resolved component-lijst staat in `webservices-rest-sbom.json`
(203 componenten). **Transitief (via platform 2.8.3), relevant voor risico** –
versies uit de SBOM: Spring 5.3.30, Hibernate ORM 5.6.15, Struts 1.3.8,
Velocity 1.7, Groovy 2.4.21, XStream 1.4.21, jackson-mapper-asl 1.9.14
(codehaus, Jackson 1.x), commons-lang 2.4, mysql-connector-java 8.0.30,
log4j 2.22.1, jackson-databind 2.19.1, snakeyaml 2.4.

### 4.2 Verouderde dependencies en CVE-risicocategorieën

> Inschatting o.b.v. versie/EOL-status. **Geen CVE-nummers geverifieerd.**

| Component | Versie | Status | Risico-inschatting (categorie) |
| :--- | :--- | :--- | :--- |
| Apache **Struts 1** | 1.3.8 | **EOL sinds 2013** | **Hoog** – meerdere bekende kritieke kwetsbaarheden (o.a. RCE). Geen patches meer. Zwaarste signaal in de stack. |
| **Spring Framework** | 5.3.30 | OSS-EOL-lijn | **Hoog** – bekende categorieën (request-/URL-parsing, data-binding). |
| Apache **Velocity** | 1.7 | **EOL** | **Middel/Hoog** – risico's rond template-injection. |
| **Jackson 1.x** (`*-asl`) | 1.9.14 | **EOL** | **Middel/Hoog** – bekende deserialisatiekwetsbaarheden. |
| **Groovy** | 2.4.21 | oude major | **Middel** – risico's rond expressie-/scripting. |
| **XStream** | 1.4.21 | actueel binnen 1.4 | **Middel** – historisch zeer kwetsbaar (deserialisatie); verifiëren. |
| `commons-lang` | 2.4 | **EOL** | **Laag/Middel** – vervangen door `commons-lang3` (ook aanwezig). Opruimen. |
| `mysql-connector-java` | 8.0.30 | verouderd binnen 8.0 | **Middel** – upgraden. |
| `log4j-core` | 2.22.1 | post-Log4Shell | **Laag** – ok, monitoren. |
| `jackson-databind` | 2.19.1 | recent | **Laag** – actueel. |

### 4.3 Ontbrekend proces: geen geautomatiseerde scan
`documentation/test&productie.md` beschrijft een GitHub Actions-pipeline, maar er
is **geen `.github/workflows/`-map in enige branch**. Er draait dus **geen**
dependency-scan (SCA) en **geen** SAST. Kwetsbaarheden worden niet structureel
verkregen, geëvalueerd of geadresseerd — de kern van A.8.8.

### 4.4 Compliance-oordeel: **VOLDOET NIET**

| Aspect | Beoordeling |
| :--- | :--- |
| Kwetsbaarheidsinformatie wordt verkregen | **Gedeeltelijk** — eenmalige SBOM (Snyk) bestaat, maar niet structureel/herhaald |
| Blootstelling wordt geëvalueerd | **Nee** — geen CVE-verificatie, geen scanner in pipeline |
| Passende maatregelen getroffen | **Nee** — EOL-componenten (Struts 1.x, Velocity 1.7, Jackson 1.x) ongepatcht; geen upgradeplan |

### 4.5 Benodigde acties
1. **OWASP Dependency-Check of Trivy** in CI opnemen en de build laten falen bij
   kritieke bevindingen.
2. **Upgradeplan** opstellen voor EOL-componenten (Struts 1.x, Velocity 1.7,
   Jackson 1.x, Spring 5.3.x), in afstemming met de OpenMRS-platformversie
   (veel deps komen transitief via `openmrs-api` 2.8.3).
3. SBOM-generatie en -scan **periodiek** in de pipeline draaien i.p.v. eenmalig.

---

## 5. Samenvattende compliance-matrix

**Legenda:** Voldoet · Gedeeltelijk · **Voldoet niet**.

| Control | Titel | Oordeel | Kern-onderbouwing | Belangrijkste actie |
| :--- | :--- | :--- | :--- | :--- |
| **A.5.15** | Toegangsbeveiliging | **Voldoet niet** | `S-1` (`/session/diag`) en `S-3` (`/settings.form/search`): endpoints zonder autorisatie, lekken rollen/privileges resp. secrets | Authenticatie + privilege afdwingen op alle endpoints |
| **A.8.28** | Veilig coderen | **Voldoet niet** | `S-2` reflected XSS, `S-3` JSON-injection, `S-4` info-lek in foutrespons, `S-10` NPE-flow/lege catch | Output-encoding + input-validatie + SAST in CI |
| **A.8.8** | Beheer technische kwetsbaarheden | **Voldoet niet** | EOL-deps (Struts 1.x e.a.) + geen SCA/SAST in pipeline | Dependency-Check/Trivy in CI + upgradeplan |

Alle drie de beoordeelde controls staan op **voldoet niet**. De gemene deler is
het ontbreken van een afdwingende kwaliteits-/securitypoort in de ontwikkelcyclus:
ontbrekende autorisatie (A.5.15) en onveilige codepatronen (A.8.28) zouden door
een SAST-stap worden gesignaleerd, en kwetsbare dependencies (A.8.8) door een
SCA-stap — beide ontbreken.

---

## 6. Geprioriteerd verbeteradvies en pentest-voorstel

### 6.1 Prioritering (op risico)
1. **Onmiddellijk:** verwijder of beveilig de drie ingebrachte endpoints
   `S-3` (secrets, A.5.15), `S-1` (rollen/privileges, A.5.15) en `S-2`
   (XSS, A.8.28) — de duidelijkste, direct exploiteerbare bevindingen.
2. **Kort:** richt de **CI-pipeline** in met **SAST** (A.8.28) en **SCA /
   Dependency-Check/Trivy** (A.8.8); start een **upgradeplan** voor EOL-
   componenten.
3. **Borging:** voeg een endpoint-autorisatie-check toe aan de code-review-
   checklist zodat A.5.15 niet opnieuw erodeert.

### 6.2 Voorstel voor penetratietest (bewijsvoering)
Gecontroleerd en geautoriseerd, uitsluitend op een **test-/acceptatieomgeving**:

| Pentest-scenario | Doel | Gekoppelde control |
| :--- | :--- | :--- |
| Ongeauthenticeerd `GET /session/diag` | Aantonen dat rollen/privileges lekken zonder login | A.5.15 |
| Ongeauthenticeerd `/settings.form/search?prefix=` | Aantonen dat global-property-waarden (secrets) uitlekken | A.5.15 |
| XSS-payload op `/apiDocs/debug?tag=` | Bevestigen scriptuitvoering in browser | A.8.28 |
| Dependency-exploit (bevestigd via scanner) | Exploiteerbaarheid van EOL-componenten beoordelen | A.8.8 |

---

## 7. Conclusie

Beoordeeld op drie kerncontrols voldoet de module aan **geen** ervan:
**A.5.15 (Toegangsbeveiliging)**, **A.8.28 (Veilig coderen)** en **A.8.8 (Beheer
van technische kwetsbaarheden)** staan alle op *voldoet niet*. De directe oorzaak
zijn drie ingebrachte, exploiteerbare endpoints (`S-1`/`S-2`/`S-3`) plus een
verouderde, grotendeels via het platform geërfde dependency-stack. De
onderliggende, structurele oorzaak is het ontbreken van een geautomatiseerde
security-poort in de ontwikkelcyclus (SAST + SCA + endpoint-review). Het
adresseren van de drie endpoints en het inrichten van die poort lost de meeste
bevindingen onder alle drie de controls in één beweging op. Exacte CVE/CVSS-
bevestiging en de voorgestelde pentest vormen de logische vervolgstap om dit
oordeel met bewijs te staven.
