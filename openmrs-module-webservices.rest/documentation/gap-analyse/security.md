# Gap-analyse Deel 2 – Security & NEN-7510:2024-compliance

**Object van onderzoek:** OpenMRS-module `webservices.rest` (versie 3.2.0)
**Repository:** OpenMRS13/openmrs-module-webservices.rest – branch `Development`
**Norm:** NEN 7510-1:2024 (Managementsysteem; control-nummering volgens
NEN-EN-ISO/IEC 27001:2023 Bijlage A, in deze repo: `documentation/NEN 7510-1_2024 nl.pdf`)
**Datum:** 11-06-2026
**Status:** concept – geschikt als auditbijlage

> **Belangrijke afwijking t.o.v. de opdracht.** Het aangekondigde
> `docs/norm/gekozen-controls.md` ontbreekt in de repository. In overleg is
> besloten dat wij zelf een relevante set beheersmaatregelen uit Bijlage A van
> NEN 7510-1 **voorstellen** (§6); deze is gemarkeerd als *voorgesteld* en kan
> later worden vervangen door de definitieve keuze. De norm-PDF in de repo is
> **Deel 1 (Managementsysteem)**; de feitelijke implementatierichtlijnen per
> beheersmaatregel staan in **NEN 7510-2** (niet aanwezig). Wij citeren daarom de
> control-titels en -doelen uit Bijlage A.

---

## 1. Scope en methodologie

- **In scope:** broncode van de module (`omod`, `omod-common`), de
  dependency-inventaris (SBOM), en de meegeleverde deployment-/CI-configuratie
  (`deployment/`, `documentation/test&productie.md`).
- **Statische review** + dependency-analyse. **Geen** dynamische test
  (pentest/DAST) en **geen** vulnerability-scanner uitgevoerd.
- **`mvn` was niet beschikbaar**; de CycloneDX-plugin
  (`mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom`) kon **niet** worden
  gedraaid. In plaats daarvan gebruiken we de **reeds in de repo aanwezige SBOM**
  `webservices-rest-sbom.json` (CycloneDX 1.5, gegenereerd door Snyk op
  2026-06-03, 203 componenten) als inventarisbasis.

### 1.1 Expliciete aannames
1. CVE-/CVSS-waarden zijn **niet** geverifieerd. Waar we "waarschijnlijk bekende
   CVE's" noemen, betreft het een **risicocategorie** op basis van versie/EOL-
   status. **Exacte CVE/CVSS-verificatie moet nog gebeuren met OWASP
   Dependency-Check of Trivy** (zie §3/§8). Wij noemen bewust **geen** specifieke
   CVE-nummers om geen ongeverifieerde claims te doen.
2. Het merendeel van de zware dependencies wordt **transitief via `openmrs-api`/
   `openmrs-web` 2.8.3 (`provided` scope)** binnengehaald en op runtime door het
   OpenMRS-platform geleverd. Mitigatie van die componenten ligt deels **upstream**
   (OpenMRS-core / platformversie), niet uitsluitend in deze module.
3. Drie endpoints (zie S-1/S-2/S-3) bevatten expliciete commentaarregels die op
   bewust ingebrachte zwakheden wijzen ("NOTE: No authorization check …"). Wij
   behandelen ze als reële bevindingen.

---

## 2. Dependency-inventarisatie (SBOM-basis)

De volledige resolved component-lijst staat in `webservices-rest-sbom.json`
(203 componenten). **Direct gedeclareerd** in de module-poms (selectie):

| Component | Versie | Scope | Bron |
| :--- | :--- | :--- | :--- |
| `commons-codec` | 1.14 | compile | `pom.xml:143` |
| `com.fasterxml.jackson.*` (core/databind/annotations) | 2.13.x | provided | `pom.xml` |
| `jackson-dataformat-yaml` | 2.13.3 | compile | `omod/pom.xml:35` |
| `joda-time` | 2.12.5 | compile | `omod-common/pom.xml:22` |
| `io.swagger:swagger-core` | 1.6.2 | compile | `omod-common/pom.xml:34` |
| `org.atteo:evo-inflector` | 1.2.2 | compile | `omod-common/pom.xml:28` |
| `org.apache.tomcat:jasper` | (platform) | provided | `omod-common/pom.xml:15` |
| `openmrs-api` / `openmrs-web` | 2.8.3 | provided | `pom.xml:60/81` |

**Transitief (via platform 2.8.3), relevant voor risico** – versies uit de SBOM:
Spring 5.3.30, Hibernate ORM 5.6.15, Hibernate Search 6.2.4, Struts 1.3.8,
Velocity 1.7, Groovy 2.4.21, XStream 1.4.21, dom4j 2.1.3, xercesImpl 2.12.2,
commons-collections 3.2.2, commons-beanutils 1.11.0, commons-lang 2.4,
log4j 2.22.1, jackson-databind 2.19.1, jackson-mapper-asl 1.9.14 (codehaus, Jackson 1.x),
snakeyaml 2.4, mysql-connector-java 8.0.30, mariadb-java-client 3.5.4,
postgresql 42.7.7, netty 4.1.118, guava 33.4.8, lucene 8.11.2,
elasticsearch-rest-client 8.10.4.

---

## 3. Verouderde dependencies en CVE-risicocategorieën

> Inschatting o.b.v. versie/EOL-status. **Geen CVE-nummers geverifieerd** –
> bevestiging vereist via OWASP Dependency-Check/Trivy (control **A.8.8**).

| Component | Versie | Status | Risico-inschatting (categorie) |
| :--- | :--- | :--- | :--- |
| Apache **Struts 1** (`struts-core/taglib/tiles`) | 1.3.8 | **EOL sinds 2013** | **Hoog** – Struts 1.x kent meerdere bekende kritieke kwetsbaarheden (o.a. RCE via class-/ActionForm-manipulatie). Geen patches meer. Zwaarste signaal in de stack. |
| **Spring Framework** | 5.3.30 | OSS-EOL-lijn | **Hoog** – 5.3.x kent meerdere bekende kwetsbaarheidscategorieën (request-/URL-parsing, data-binding). Exacte CVE's te verifiëren. |
| Apache **Velocity Engine** | 1.7 | **EOL** | **Middel/Hoog** – oude template-engine; bekende risico's rond template-injection. |
| **Jackson 1.x** (`org.codehaus.jackson:*-asl`) | 1.9.14 | **EOL** | **Middel/Hoog** – Jackson 1.x kent bekende deserialisatiekwetsbaarheden; vervangen door Jackson 2.x. |
| **Groovy** | 2.4.21 | oude major | **Middel** – Groovy 2.4-lijn; bekende risico's rond expressie-/scripting. |
| **XStream** | 1.4.21 | actueel binnen 1.4 | **Middel** – historisch zeer kwetsbaar (deserialisatie); 1.4.21 is recent maar verdient verificatie. |
| `commons-lang` | 2.4 | **EOL (1.x/2.x)** | **Laag/Middel** – vervangen door `commons-lang3` (ook aanwezig, 3.18.0). Opruimen. |
| `mysql-connector-java` | 8.0.30 | verouderd binnen 8.0 | **Middel** – oudere 8.0.x; verbindingsgerelateerde CVE-categorie; upgraden. |
| `Hibernate ORM` | 5.6.15 | 5.x | **Laag/Middel** – verifiëren. |
| `log4j-core` | 2.22.1 | post-Log4Shell | **Laag** – ruim na de bekende Log4Shell-reeks; ok, monitoren. |
| `jackson-databind` | 2.19.1 | recent | **Laag** – actueel. |
| `snakeyaml` | 2.4 | recent | **Laag** – na de bekende 1.x-deserialisatieproblematiek. |

**Aanbeveling:** draai OWASP Dependency-Check of Trivy in CI en koppel de output
aan control **A.8.8**; behandel Struts 1.x, Spring 5.3.x, Velocity 1.7 en
Jackson 1.x als eerste te adresseren (deels via een platform-upgrade upstream).

---

## 4. Security code review – bevindingen

### S-1 — Ongeautoriseerd diagnostics-endpoint lekt gebruikers-/rechteninfo
**Locatie:** `omod/.../v1_0/controller/openmrs1_9/SessionController1_9.java:170-182`
(`GET /rest/v1/session/diag`).
Het endpoint heeft **geen autorisatiecheck** (commentaar regel 168 bevestigt dit),
declareert een **ongebruikte `token`-parameter** (schijnbeveiliging, regel 172) en
retourneert bij een geauthenticeerde sessie **gebruikersnaam, rollen én
privileges** (regels 177-179), plus servertijd. Dit is *Broken Access Control* +
*information disclosure*: het versnelt het in kaart brengen van rechten/rollen
door een aanvaller en lekt interne autorisatiestructuur.

### S-2 — Reflected Cross-Site Scripting (XSS) in debug-endpoint
**Locatie:** `omod/.../controller/SwaggerDocController.java:24-28`
(`GET /module/webservices/rest/apiDocs/debug?tag=…`).
De `tag`-parameter wordt **ongesanitiseerd** teruggegeven in een HTML-respons
(`return "<h1>Debugging Tag: " + tag + "</h1>"`). Een waarde als
`<script>…</script>` wordt door de browser uitgevoerd → *reflected XSS*. Geen
output-encoding, geen `Content-Type`-beperking, geen autorisatie.

### S-3 — Ongeautoriseerde global-property-zoekfunctie lekt configuratie/secrets
**Locatie:** `omod/.../controller/SettingsFormController.java:50-63`
(`GET /module/webservices/rest/settings.form/search?prefix=…`).
Het endpoint mist een `Context.isAuthenticated()`-check (regels 44-53) en
retourneert **naam én waarde** van global properties die op `prefix` matchen
(regels 57-58). Global properties bevatten in OpenMRS regelmatig **gevoelige
configuratie** (SMTP-/API-credentials, sleutels). Resultaat: *Broken Access
Control* met direct *secret/PHI-config-disclosure*. De JSON wordt bovendien via
**string-concatenatie** opgebouwd zonder escaping (JSON-injection mogelijk).

### S-4 — Informatielekkage in elke foutrespons
**Locatie:** `omod-common/.../RestUtil.java:820-870` (`wrapErrorResponse`).
Volledige stacktraces zijn standaard **uit** (gated door global property
`ENABLE_STACK_TRACE_DETAILS`, default `false` – goed). Echter: **elke** foutrespons
bevat altijd `code` = `klasse:regelnummer` (regel 855) en `rawMessage` = de ruwe
exception-message (regel 865). Dit lekt interne klassenamen, regelnummers en
mogelijk gevoelige messages aan de client. Ernst laag-middel, maar relevant voor
informatiebeperking. (Upstream-gedrag.)

### S-5 — Geen transportbeveiliging (TLS) in productie-deployment
**Locatie:** `deployment/environments/docker-compose.prod.yml`.
De productie-container publiceert **poort 80 (HTTP)** zonder TLS-terminatie/reverse
proxy. REST-verkeer met persoonlijke gezondheidsinformatie en Basic-auth-
credentials zou onversleuteld over het netwerk gaan. (Proces/platform.)

### S-6 — Configuratie-/secret-hygiëne in deployment
**Locatie:** `deployment/environments/docker-compose.prod.yml`,
`deployment/secrets/prod.env.example`.
- MySQL **root-wachtwoord = applicatie-wachtwoord** (`MYSQL_ROOT_PASSWORD: ${OPENMRS_DB_PASSWORD}`):
  geen functiescheiding tussen DB-root en app-account.
- Container-image met tag **`:latest`** (`openmrs/...:latest`, `mysql:8.0`):
  niet reproduceerbaar, geen vastgepinde digest → supply-chain-/configuratierisico.
Positief: secrets staan in `.env`/GitHub Environments, niet in code
(`test&productie.md`). (Proces/platform.)

### S-7 — Verouderde/EOL-componenten zonder geautomatiseerde kwetsbaarhedenscan
Zie §3. Er is **geen** dependency-scan in een pipeline (zie S-9). Control **A.8.8**.

### S-8 — Authenticatie is single-factor (HTTP Basic)
**Locatie:** `omod-common/.../BaseRestController.java` (WWW-Authenticate `Basic`).
De REST-laag leunt op platform-**Basic authentication** (één factor). NEN 7510
**A.8.5** stelt zorgspecifiek: *"Er moet ten minste tweefactorauthenticatie worden
gebruikt voor systemen die persoonlijke gezondheidsinformatie verwerken."* De
module zelf kan dit niet volledig afdwingen (platform-/IdP-zaak), maar het is een
relevante gap. (Architectuur/platform.)

### S-9 — Geen secure CI-pipeline / kwetsbaarhedenscan aanwezig
`documentation/test&productie.md` beschrijft een GitHub Actions-pipeline en
branch protection, maar er is **geen `.github/workflows/`-map in enige branch**
(`Development`, `main`, `OTAP`, `SysteemAnalyse`, `cicd`). De pipeline is dus
**beschreven maar niet geïmplementeerd**; bovendien staat branch protection volgens
het document zelf **uit** ("omdat we niet een betaalde versie hebben van GitHub").
Controls **A.8.25/A.8.29/A.8.32**. (Proces/platform.)

### S-10 — Overige codehygiëne met beveiligingsraakvlak (laag)
- `ChangePasswordController1_8.changeOthersPassword:69-85` gooit een kale
  `NullPointerException` als "niet gevonden" en doet geen expliciete
  authenticatiecheck (steunt op service-privilege `EDIT_USER_PASSWORDS`).
- `SettingsFormController` onderdrukt validatiefouten met lege catch-blokken
  (`:151`, `:160`).

---

## 5. Gap-tabel security

Ernst-schaal: **Kritiek / Hoog / Middel / Laag** (kwalitatief; CVSS niet berekend).

| ID | Bevinding | Locatie (bestand:regel) | Risico-omschrijving | Ernst | Control(s) | Aanbevolen mitigatie |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| S-1 | Ongeautoriseerd `/session/diag` lekt rollen/privileges | `SessionController1_9.java:170-182` | Broken Access Control + info disclosure; ondersteunt privilege-mapping | **Hoog** | A.5.15, A.8.3, A.5.18, A.8.2 | Endpoint verwijderen of achter authenticatie + privilege zetten; geen rollen/privileges teruggeven |
| S-2 | Reflected XSS via `tag` | `SwaggerDocController.java:24-28` | Uitvoer van scripts in browser van slachtoffer; sessiediefstal/CSRF-opstap | **Hoog** | A.8.26, A.8.28 | Endpoint verwijderen; anders output-encoding (OWASP Encoder, al in stack) + `Content-Type` + autorisatie |
| S-3 | Ongeautoriseerde GP-zoek lekt secrets | `SettingsFormController.java:50-63` | Broken Access Control + secret/PHI-config-disclosure + JSON-injection | **Kritiek** | A.5.15, A.8.3, A.8.5, A.5.34, A.8.11 | Authenticatie + privilege afdwingen; waarden niet teruggeven/maskeren; JSON via serializer |
| S-4 | Interne details in elke foutrespons | `RestUtil.java:855,865` | Klassenamen/regelnummers + ruwe messages lekken | Laag/Middel | A.8.26, A.8.28, A.5.34 | `code`/`rawMessage` weglaten in prod; generieke clientmelding, details alleen in serverlog |
| S-5 | Geen TLS in prod-deployment | `docker-compose.prod.yml` | Onversleuteld PHI + credentials over netwerk | **Hoog** | A.8.24, A.5.14 | TLS-terminatie (reverse proxy/ingress), HTTP→HTTPS-redirect, HSTS |
| S-6 | Secret-/image-hygiëne | `docker-compose.prod.yml`, `prod.env.example` | DB-root = app-pw; `:latest`-tags | Middel | A.8.9, A.5.17 | Aparte DB-credentials; image-tags/digests pinnen |
| S-7 | EOL/verouderde dependencies | SBOM / §3 | Bekende kwetsbaarheidscategorieën (Struts 1.x e.a.) | **Hoog** | A.8.8 | Scanner in CI; platform/transitieve upgrades; Struts/Velocity/Jackson 1.x adresseren |
| S-8 | Single-factor (Basic) auth | `BaseRestController.java` | Geen 2FA voor PHI-verwerkend systeem | Middel | A.8.5 | 2FA/OAuth2/OIDC op platform-/gateway-niveau |
| S-9 | Geen secure CI-pipeline/scan | (afwezig) + `test&productie.md` | Geen geautomatiseerde test/scan; branch protection uit | **Hoog** | A.8.25, A.8.29, A.8.32 | Pipeline implementeren (build+test+SAST+SCA); branch protection activeren |
| S-10 | Codehygiëne (NPE-flow, lege catch) | `ChangePasswordController1_8.java:81`, `SettingsFormController.java:151/160` | Onverwachte 500's / verborgen fouten | Laag | A.8.28 | Specifieke excepties; geen lege catch |

### Onderbouwing control-koppeling (citaten uit Bijlage A)
- **S-1, S-3 → A.5.15 Toegangsbeveiliging** ("regels … om de fysieke en logische
  toegang tot informatie … te beheersen") en **A.8.3 Beperking toegang tot
  informatie**: beide endpoints geven toegang zonder enige toegangsregel.
- **S-3 → A.8.11 Maskeren van gegevens** ("Gegevens moeten worden gemaskeerd …")
  en **A.5.34 Privacy en bescherming van [persoonsgegevens]**: secret-/configwaarden
  worden onbeperkt prijsgegeven.
- **S-2, S-4, S-10 → A.8.28 Veilig coderen** ("principes voor veilig coderen …
  toegepast op softwareontwikkeling") en **A.8.26 Toepassingsbeveiligingseisen**:
  ontbrekende inputvalidatie/outputencoding en informatielekkage.
- **S-5 → A.8.24 Gebruik van cryptografie** + **A.5.14 Overdragen van informatie**:
  vertrouwelijke overdracht zonder versleuteling.
- **S-7 → A.8.8 Beheer van technische kwetsbaarheden** ("informatie over technische
  kwetsbaarheden … evalueren … passende maatregelen treffen").
- **S-8 → A.8.5 Beveiligde authenticatie** (zorgspecifiek: ten minste 2FA voor PHI).
- **S-9 → A.8.25 Beveiligen tijdens de ontwikkelcyclus** + **A.8.29 Testen van de
  beveiliging tijdens ontwikkeling en acceptatie**.

---

## 6. Voorgestelde set beheersmaatregelen (Bijlage A NEN 7510-1:2024)

*Voorgesteld* in afwezigheid van `gekozen-controls.md`; te bevestigen door het team.

**Op codeniveau (mede) beoordeelbaar:**
A.5.15 Toegangsbeveiliging · A.5.16 Identiteitsbeheer · A.5.17 Authenticatie-
informatie · A.5.18 Toegangsrechten · A.8.2 Speciale toegangsrechten · A.8.3
Beperking toegang tot informatie · A.8.5 Beveiligde authenticatie · A.8.8 Beheer
van technische kwetsbaarheden · A.8.11 Maskeren van gegevens · A.8.15 Logging ·
A.8.16 Monitoren van activiteiten · A.8.24 Gebruik van cryptografie · A.8.26
Toepassingsbeveiligingseisen · A.8.28 Veilig coderen · A.5.34 Privacy en
bescherming van persoonsgegevens.

**Proces-/platformcontrols (niet op codeniveau, apart aantonen):**
A.8.25 Beveiligen tijdens de ontwikkelcyclus · A.8.29 Testen van de beveiliging ·
A.8.31 Scheiding van ontwikkel-, test- en productieomgevingen · A.8.32
Wijzigingsbeheer · A.8.33 Testgegevens · A.8.9 Configuratiebeheer.

---

## 7. Compliance-matrix

**Legenda status:** Voldoet · Gedeeltelijk · Voldoet niet · Niet beoordeelbaar op
codeniveau (proces/platform).

### 7a. Op codeniveau beoordeelbare controls

| Control | Status | Onderbouwing (verwijzing naar bevinding) | Benodigde actie |
| :--- | :--- | :--- | :--- |
| **A.5.15** Toegangsbeveiliging | **Voldoet niet** | S-1 en S-3: endpoints zonder enige toegangsregel | Authenticatie + autorisatie afdwingen op alle endpoints |
| **A.5.16** Identiteitsbeheer | Niet beoordeelbaar | Identiteits-lifecycle is platformfunctie | Aantonen via OpenMRS-/IdP-inrichting |
| **A.5.17** Authenticatie-informatie | Gedeeltelijk | Wachtwoordwijziging via `ChangePasswordController`/`PasswordResetController` aanwezig en redelijk; S-6 (credential-hygiëne deployment) | DB-credentials scheiden; wachtwoordbeleid op platform |
| **A.5.18** Toegangsrechten | Gedeeltelijk | Privilege-model bestaat (proxy-privileges), maar S-1 omzeilt het | Endpoints conform privilege-model brengen |
| **A.8.2** Speciale toegangsrechten | Gedeeltelijk | S-1 lekt privilege-overzicht | Endpoint dichtzetten |
| **A.8.3** Beperking toegang tot informatie | **Voldoet niet** | S-1, S-3 | Toegangsbeperking implementeren |
| **A.8.5** Beveiligde authenticatie (2FA voor PHI) | **Voldoet niet** | S-8: alleen Basic (single-factor) | 2FA/OIDC op platform-/gatewayniveau |
| **A.8.8** Beheer technische kwetsbaarheden | **Voldoet niet** | S-7: EOL-deps, geen scan | Dependency-Check/Trivy in CI; upgradeplan |
| **A.8.11** Maskeren van gegevens | **Voldoet niet** | S-3: GP-waarden onbeperkt teruggegeven | Maskeren/niet teruggeven van gevoelige waarden |
| **A.8.15** Logging | Gedeeltelijk | Foutlogging in `BaseRestController.handleException` (5xx→error, 4xx→info); geen aantoonbare security-/audit-logging van toegang | Security-/audittrail op gevoelige acties; geen secrets loggen |
| **A.8.16** Monitoren van activiteiten | Niet beoordeelbaar | Monitoring is platform/SOC | Aantonen via platform/pipeline-monitoring |
| **A.8.24** Gebruik van cryptografie | **Voldoet niet** (deployment) | S-5: geen TLS in prod-compose | TLS afdwingen |
| **A.8.26** Toepassingsbeveiligingseisen | **Voldoet niet** | S-2, S-3, S-4 | Beveiligingseisen + reviewchecklist |
| **A.8.28** Veilig coderen | **Voldoet niet** | S-2 (XSS), S-3 (injection/access), S-10 | Secure-coding-richtlijn + SAST in CI |
| **A.5.34** Privacy/bescherming persoonsgegevens | Gedeeltelijk | S-3, S-4: lekrisico's; geen PHI hard aangetoond gelekt | Disclosure-risico's mitigeren |

### 7b. Proces-/platformcontrols (niet op codeniveau – apart aantonen)

> Deze controls gaan over de inrichting van het ontwikkelplatform en proces en
> moeten worden bewezen via bv. GitHub-instellingen, pipeline-configuratie en
> beleidsdocumenten, niet via de broncode.

| Control | Status | Onderbouwing | Benodigde actie / bewijslast |
| :--- | :--- | :--- | :--- |
| **A.8.25** Beveiligen tijdens de ontwikkelcyclus | **Voldoet niet** | S-9: geen pipeline geïmplementeerd | GitHub Actions-workflow met build/test/SAST/SCA toevoegen |
| **A.8.29** Testen van de beveiliging | **Voldoet niet** | S-9: geen security-tests in CI | SAST/DAST/SCA-stappen + pentest (zie §8) |
| **A.8.31** Scheiding ontwikkel/test/prod | Gedeeltelijk | `test&productie.md` beschrijft Test- vs Productieomgeving + aparte compose-files | Scheiding daadwerkelijk via pipeline aantonen; secrets-isolatie bewijzen |
| **A.8.32** Wijzigingsbeheer | Gedeeltelijk | Branch-/PR-workflow beschreven, maar branch protection staat **uit** | Branch protection + verplichte review + checks activeren |
| **A.8.33** Testgegevens | Gedeeltelijk | Testdatasets (XML) aanwezig; scheiding test/prod-data beschreven | Bevestigen dat geen productie-/PHI-data in tests zit |
| **A.8.9** Configuratiebeheer | Gedeeltelijk | Secrets via env/GitHub Environments (goed); S-6: `:latest`-tags, gedeelde DB-root-pw | Image-pinning, credential-scheiding, baseline-config vastleggen |

---

## 8. Geprioriteerd verbeteradvies en pentest-voorstel

### 8.1 Prioritering (op risico)
1. **Onmiddellijk (Kritiek/Hoog):**
   - Verwijder of beveilig de drie ingebrachte endpoints **S-3** (secrets),
     **S-1** (rollen/privileges) en **S-2** (XSS). Dit zijn de duidelijkste,
     direct exploiteerbare bevindingen.
   - Schakel **TLS** in voor productie (**S-5**).
2. **Kort (Hoog):**
   - Richt de **CI-pipeline** in met SAST + **SCA (Dependency-Check/Trivy)** en
     activeer **branch protection** (**S-9**, **S-7**) — dekt tevens
     onderhoudbaarheids-NFR's O-1/O-4.
   - Start een **upgradeplan** voor EOL-componenten (Struts 1.x, Velocity 1.7,
     Jackson 1.x, Spring 5.3.x) in afstemming met de OpenMRS-platformversie.
3. **Middellange termijn (Middel):**
   - **2FA/OIDC** voor PHI-toegang (**S-8**); credential-/image-hygiëne (**S-6**);
     foutrespons-hardening (**S-4**); codehygiëne (**S-10**).

### 8.2 Voorstel voor penetratietest (bewijsvoering)
De volgende bevindingen lenen zich uitstekend voor een **gecontroleerde,
geautoriseerde** pentest om de gap-analyse met bewijs te onderbouwen:

| Pentest-scenario | Doel | Gekoppelde bevinding/control |
| :--- | :--- | :--- |
| Ongeauthenticeerd `GET /session/diag` | Aantonen dat rollen/privileges lekken zonder login | S-1 / A.5.15, A.8.3 |
| XSS-payload op `/apiDocs/debug?tag=` | Bevestigen scriptuitvoering in browser | S-2 / A.8.28 |
| Ongeauthenticeerd `/settings.form/search?prefix=` | Aantonen dat global-property-waarden (secrets) uitlekken | S-3 / A.5.15, A.8.11 |
| Authenticatie-/sessiebeheer (Basic, logout, sessie-invalidatic) | 2FA-afwezigheid en sessiegedrag valideren | S-8 / A.8.5 |
| Transport (TLS-stripping / cleartext) | Bevestigen onversleutelde PHI/credentials | S-5 / A.8.24 |
| Dependency-exploit (bevestigd via scanner) | Exploiteerbaarheid van EOL-componenten beoordelen | S-7 / A.8.8 |

> Pentest uitsluitend op een **test-/acceptatieomgeving** met expliciete
> opdrachtgeveraccordering (NEN **A.8.34**: audittests vooraf afstemmen met
> verantwoordelijk management).

---

## 9. Conclusie Deel 2

De module bevat **drie direct exploiteerbare, ingebrachte zwakheden** (S-1/S-2/S-3)
die meerdere kerncontrols (A.5.15, A.8.3, A.8.11, A.8.26, A.8.28) op *"voldoet
niet"* zetten. Daarnaast zijn er structurele aandachtspunten op
**transportbeveiliging** (A.8.24), **kwetsbaarhedenbeheer** van een verouderde,
grotendeels via het platform geërfde dependency-stack (A.8.8) en een **nog niet
geïmplementeerde secure pipeline** (A.8.25/A.8.29/A.8.32). Veel proces-/platform-
controls zijn op codeniveau *niet beoordeelbaar* en moeten apart worden aangetoond
via de inrichting van GitHub en de CI/CD-pipeline. Exacte CVE/CVSS-bevestiging en
de in §8.2 voorgestelde pentest vormen de logische vervolgstap om deze analyse met
bewijs te staven.
