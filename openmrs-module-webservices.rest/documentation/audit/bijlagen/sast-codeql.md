# SAST in CI — GitHub Code Scanning (CodeQL)

**Methode:** GEAUTOMATISEERDE SAST via **GitHub Code Scanning met CodeQL** (geen handmatige tool).
**Bewijs:** screenshot `audit/bijlagen/sast-codeql-codescanning.png` (door opdrachtgever aangeleverd, 2026-06-19).
**Repository:** `openmrs-module-webservices.rest` · **Branch in screenshot:** `main` · **Query:** `is:open branch:main tool:CodeQL`
**Status:** "All tools are working as expected" · **Tools:** 1 (CodeQL) · **Alerts:** 3 open + 2 closed.

> **Configuratie.** In geen van de branches (`main`, `Development`, `CodeQL`) is een `.github/workflows/`-CodeQL-bestand aangetroffen (`git ls-tree -r origin/main`, `origin/CodeQL`). CodeQL draait daarom hoogstwaarschijnlijk via GitHub **"default setup"** (configuratie in de repo-instellingen, géén workflow-bestand). Dit verklaart waarom de eerdere bestand-gebaseerde controle (zie AUD-07/AUD-19) geen workflow vond, terwijl CodeQL feitelijk **wél** actief is. Er bestaat ook een aparte branch `origin/CodeQL`.

## Alerts uit de screenshot, geverifieerd tegen de code

| # | Alert | Ernst (CodeQL) | Locatie (screenshot) | Code-verificatie (deze audit) |
| :-- | :-- | :-- | :-- | :-- |
| #3 | Cross-site scripting | **High** | `.../controller/SwaggerDocController.java:27` (branch `main`) | Op `Development` (audit-commit `19d1b21`) is dit **geremedieerd**: `SwaggerDocController.java:28` gebruikt `HtmlUtils.htmlEscape(tag)`. Het open alert weerspiegelt branch `main` — de productiebranch **loopt achter** op Development. |
| #5 | Overly permissive regular expression range | **Medium** | `.../helper/ServerLogActionWrapper.java:70` | **Bevestigd** op `Development`: `ServerLogActionWrapper.java:70` bevat `[A-z]` (te ruime range — omvat ` [ \ ] ^ _ ` `). Zie bevinding **AUD-20**. |
| #4 | Overly permissive regular expression range | **Medium** | `.../helper/ServerLogActionWrapper.java:70` | Idem #5 — tweede `[A-z]`-match op dezelfde regel (`((?:[A-z][A-z].+))`). Zie **AUD-20**. |
| (closed) | 2 gesloten alerts | — | n.v.t. | Inhoud niet zichtbaar in de screenshot; vermoedelijk eerder geremedieerde bevindingen. **Niet vastgesteld** welke exact. |

Letterlijk codefragment — `omod-common/.../helper/ServerLogActionWrapper.java:70`:
```java
		String regExPatternType = "(INFO|ERROR|WARN|DEBUG)\\s.*?[-].*?\\s((?:[A-z][A-z].+))\\s[|](.*?)[|]\\s((.*\\n*)+)";
```

## Conclusie
CodeQL is een **volwaardige, automatische SAST** en draait aantoonbaar in CI. Dit **vervangt** de eerder door de auditor uitgevoerde handmatige grep-sweep (op verzoek verwijderd, want CodeQL is sterker en heeft o.a. de te ruime regex-range gevonden die de handmatige sweep miste).

**Beperkingen (Niet vastgesteld):** de exacte CodeQL-trigger-/branchdekking (draait het op elke PR/branch?) en of de build/PR wordt **geblokkeerd** bij High-alerts, zijn niet uit de repository te verifiëren; de screenshot is een momentopname. **SCA (dependency-CVE's), secret-scanning en SBOM-generatie** zijn in deze screenshot **niet** aangetoond — die CI-onderdelen blijven open (zie AUD-07).
