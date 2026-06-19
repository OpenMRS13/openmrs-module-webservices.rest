# Software Bill of Materials (SBOM) & Update-advies

## 1. Generatie van de Machine-Bruikbare SBOM
Binnen de GitHub Actions pipeline is een automatische stap ingericht (`Generate SBOM`) die bij elke push naar de hoofdvertakkingen een actuele **Software Bill of Materials (SBOM)** genereert. 

* **Formaat:** Er is gekozen voor het **CycloneDX**-formaat in JSON-structuur (`sbom.cyclonedx.json`).
* **Machine-bruikbaarheid:** Omdat het bestand volledig in gestructureerd JSON-formaat wordt opgeleverd, is het direct machine-bruikbaar. Dit betekent dat tooling (zoals Dependency-Track of OWASP Dependency-Check) dit bestand automatisch kan inlezen om continu te controleren op nieuw ontdekte kwetsbaarheden, zonder dat een mens de code handmatig hoeft te doorzoeken. 

Het gegenereerde bestand bevat een volledige, transparante lijst van alle externe bibliotheken (dependencies) die binnen deze OpenMRS REST-module worden gebruikt.

---

## 2. Advies voor het Updaten van Afhankelijkheden
Om de veiligheid en onderhoudbaarheid van het systeem op de lange termijn te waarborgen, is er een gestructureerd update-advies opgesteld. Dit advies is gebaseerd op drie pijlers: de SBOM, **CVE’s** (bekende kwetsbaarheden) en **CVSS-scores** (de ernst van de kwetsbaarheid op een schaal van 0 tot 10).

### Update-prioritisering op basis van CVSS-scores
Niet elke update is even dringend. Om de werklast voor het ontwikkelteam behapbaar te houden, worden updates gecategoriseerd op basis van de CVSS-score:

| CVSS Score | Risiconiveau | Vereiste Actie & Tijdsbestek |
| :--- | :--- | :--- |
| **9.0 - 10.0** | **Critical** | **Directe actie vereist.** De pipeline blokkeert de build (ingesteld via `fail-on-severity: high/critical`). Binnen 24-48 uur handmatig patchen of de bibliotheek isoleren. |
| **7.0 - 8.9** | **High** | **Hoge prioriteit.** Updaten binnen de huidige sprint (maximaal 2 weken). Vaak gaat het om kwetsbaarheden die misbruikt kunnen worden om data te lekken. |
| **4.0 - 6.9** | **Medium** | **Inplannen.** Updaten tijdens regulier onderhoud of de volgende grote release, tenzij de kwetsbaarheid direct vanaf het internet bereikbaar is. |
| **0.1 - 3.9** | **Low** | **Monitoren.** Geen directe actie vereist. Meenemen wanneer er om andere redenen aan de desbetreffende module wordt gewerkt. |

---

### Actuele status van de dependencies (Praktijkcheck)
Op het GitHub Security Dashboard zijn momenteel exact **4 Dependabot alerts** actief. Op basis van de opgestelde CVSS-prioritering is daar het volgende actieplan voor gemaakt:

| Bibliotheek (Dependency) | CVE-Code | CVSS-Score / Niveau | Actieplan conform advies |
| :--- | :--- | :--- | :--- |
| org.openmrs.web:openmrs-web | CVE-2026-40076 | 9.4 (Critical) | **Acuut oplossen (binnen 24-48 uur):** Aangezien de pipeline hier momenteel niet hard op faalt, moet dit kritieke lek handmatig in de `pom.xml` worden geüpdatet naar de door GitHub geadviseerde veilige versie om misbruik van de medische API te voorkomen. |
| org.openmrs.api:openmrs-api | CVE-2026-41258 | 9.1 (Critical) | **Acuut oplossen (binnen 24-48 uur):** Aangezien de pipeline hier momenteel niet hard op faalt, moet dit kritieke lek handmatig in de `pom.xml` worden geüpdatet naar de door GitHub geadviseerde veilige versie om misbruik van de medische API te voorkomen. |
| org.openmrs.web:openmrs-web | CVE-2026-40075 | 8.2 (High) | **Hoge prioriteit:** Inplannen voor de huidige sprint. Updaten naar een veilige versie. | |
| com.fasterxml.jackson.core:jackson-databind | CVE-2025-52999 | 7.5 (High) | **Hoge prioriteit:** Inplannen voor de huidige sprint (binnen 2 weken). Updaten naar de veilige versie. | |
| com.fasterxml.jackson.core:jackson-core | Geen CVE | 6.9 (Medium) | **Inplannen:** Meenemen tijdens de volgende reguliere onderhoudsronde. |
| junit:junit | CVE-2020-15250 | 4.0 (Medium) | **Inplannen:** Meenemen tijdens de volgende reguliere onderhoudsronde. ||

Door deze specifieke kwetsbaarheden gestructureerd aan te pakken via de bovenstaande tabel, voldoet het project direct aan het opgestelde update-beleid en blijft de medische API veilig.
---

### Belangrijke observatie: Waarom de build niet faalt bij een 'Critical' alert
Op het dashboard wordt een van de kwetsbaarheden aangemerkt als **Critical**. In theorie zou zo'n ernstig lek de build moeten blokkeren, maar in onze huidige GitHub Actions pipeline loopt de build toch succesvol door. Dit is om de volgende redenen correct en verklaarbaar:

1. **Gedrag bij bestaande code (Dashboard vs. Pipeline):** GitHub Dependabot werkt als een waarschuwingssysteem op de achtergrond voor de *bestaande* code. Het dashboard registreert het lek netjes zodat het team dit ziet, maar het blokkeert de dagelijkse commits op de hoofdvertakking niet automatisch. De pipeline is (standaard) zo ingesteld dat hij pas hard faalt wanneer een ontwikkelaar in een *nieuwe* Pull Request zélf actief een nieuwe onveilige bibliotheek probeert toe te voegen.
2. **Maven compiler logica:** De stap `mvn clean verify` in de pipeline kijkt puur naar de Java-code zelf: compileert alles goed en slagen de tests? Maven trekt zich er standaard niets van aan of een bibliotheek een bekend beveiligingslek (CVE) heeft. Zolang de code technisch werkt, geeft Maven het stempel `BUILD SUCCESS`.

### Advies en Actieplan voor deze Critical Alert
Omdat de pipeline bij bestaande code dus *niet* uit zichzelf hard faalt, mag dit kritieke lek absoluut niet worden genegeerd. Dit onderstreept juist het nut van dit update-advies:
* **Actie:** Dit specifieke pakket moet met de allerhoogste prioriteit (binnen 24 tot 48 uur in een echte productieomgeving) handmatig door het team worden geüpdatet in de `pom.xml` naar de door GitHub geadviseerde veilige versie. Zolang dit niet is gebeurd, blijft er een openstaand risico aanwezig op het dashboard.

---
### Concreet Advies voor het OpenMRS Project

Gezien de aard van de `openmrs-module-webservices.rest` (een medische API die gevoelige patiëntgegevens verwerkt), luidt het advies als volgt:

1. **Automatische scanning inrichten:** Gebruik de gegenereerde `sbom.cyclonedx.json` en koppel deze aan een automatische scanner (zoals GitHub Dependency Graph of SonarCloud Quality Gates). Hierdoor krijgt het team direct een melding zodra een van de gebruikte bibliotheken een nieuwe CVE (kwetsbaarheid) krijgt toegewezen.
2. **Hanteer een 'Update-of-Patch' beleid:**
   * **Minor & Patch updates:** Bibliotheken moeten minimaal één keer per kwartaal preventief naar de nieuwste stabiele *minor* of *patch* versie worden geüpdatet, zolang er geen brekende wijzigingen (*breaking changes*) zijn. Dit voorkomt dat het project te ver achterloopt en updates in de toekomst te complex worden.
   * **Major updates (Legacy risico):** Omdat OpenMRS op oudere Java-versies (Java 8) draait, kunnen grotere updates (*major*) ervoor zorgen dat de code crasht. Het advies is om major updates pas door te voeren na een grondige impactanalyse en mits er voldoende testdekking (richting de gekozen 70%) aanwezig is om regressiefouten op te vangen.
3. **Omgang met 'High' en 'Critical' CVE's:**
   Indien de pipeline (via de `dependency_review` job) faalt op een CVE met een score van 7.0 of hoger, mag de code onder geen beding naar de productieomgeving worden gedeplyed. De pipeline dwingt dit nu al succesvol af.