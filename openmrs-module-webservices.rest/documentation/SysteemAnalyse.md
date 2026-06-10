# Systeem analyse van OpenMRS REST Web Services Module

# 1. Context
### 1.1 Project Beschrijving
Het gekozen project is `openmrs-module-webservices.rest` dit is een module van OpenMRS. OpenMRS is een open-source patiëntendossier systeem dat wereldwijd wordt ingezet, voornamelijk door landen met beperkte middelen. De module stelt de volledige OpenMRS API beschikbaar als REST-Webservices, waardoor externe applicaties patiëntgegevens kunnen opvragen en registreren.

### 1.2 Gevoelige gegevens die worden verwerkt (kroonjuwelen)
Via de REST-endpoints van deze module worden de de volgende categorieën **bijzondere persoongegevens** en medische informatie neergezet:

| # | Gegevenscategorie | REST-resource | Classificatie | Dreigingsscenario |
| :--- | :--- | :--- | :--- | :--- |
| **1** | **Patiëntidentificatie**: naam, geboortedatum, geslacht, patiënt-ID | `/ws/rest/v1/patient` | Bijzondere persoonsgegevens (AVG art. 9) | Datalek, verkoop op darkweb, identiteitsfraude |
| **2** | **Medische observaties**: laberatoriumwaarde, vitale functies, klachten | `/ws/rest/v1/obs` | Medisch beroepsgeheim | Manipulatie → verkeerde behandelbeslissing |
| **3** | **Diagnose & aandoeningen**: gecodeerde diagnoses, problemenlijst | `/ws/rest/v1/condition` | Bijzondere persoonsgegevens (AVG art. 9) | Datalek → discriminatie op basis van diagnose |
| **4** | **Medicatiegegevens**: voorschriften, doseringen | `/ws/rest/v1/drug` & `/ws/rest/v1/drugorder` | Medisch beroepsgeheim | Manipulatie → verkeerde dosering, levensgevaar |
| **5** | **Zorgcontacten**: datum, locatie, behandelaar | `/ws/rest/v1/encounter` & `/ws/rest/v1/visit` | Persoonsgegevens en medische gegevens | Privacyschending, herleidbaar behandelpatroon |
| **6** | **Zorgverleners gegevens**: naam, rol, bevoegdheden | `/ws/rest/v1/provider` | Persoonsgegevens | Accountovername, onbevoegde schrijftoegang tot dossiers |
| **7** | **Authenticatiegegevens**: sessietokens, basisauthenticatie | `/ws/rest/v1/session` | Beveiligingskritisch | Accountovername, ongeautoriseerde toegang tot volledige API |
| **8** | **Locatiegegevens**: ziekenhuislocaties, afdelingen | `/ws/rest/v1/location` | Organisatiegevoelig | Doelgerichte aanval op specifieke zorginstellingen |

---

### Relevante wet- en regelgevingen:
- **AVG**: Verordering medische gegevens zijn bijzondere persoonsgegevens.
- **NEN 7510**: Nederlandse norm voor de informatiebeveiliging in de zorg. Vereist risicoanalyse, toegangscontrole en auditlogging voor zorginformatiesystemen.


# 2. CIA-Analyse
De CIA bestaat uit drie verschillende waardes om informatiebeveiliging te meten:
| Dimensie | Vraag | Healthcare-voorbeeld | 
| :--- | :--- | :--- |
| **Confidentiality** (vertrouwelijkheid) |  Kan onbevoegde toegang krijgen tot de data? | Patiëntdossier ingezien door niet-behandelend arts |
| **Integrity** (integriteit) | Kan de data ongemerkt gewijzigd worden? | Medicatiedosering aangepast in het EPD | 
| **Availability** (Beschikbaarheid) | Kan het systeem of de data onbereikbaar worden? | Ransomware legt het EPD plat tijdens een operatie |

### 2.1 Confidentiality (vertrouwelijkheid) -- Hoog
De REST-module gebruikt patiëntgegevens via HTTP-endpoints. Zonder goede beveiligingsmaatregelen kunnen deze gegevens worden onderschept of op het internet komen.

**Bedreigingen:**
- Onbeveiligde API-calls wat kan leiden tot inzien van patiëntendata
- Zwakke authenticatie kan leiden tot credential-diefstal
- Ontbreken van autorisatieniveaus kan leiden tot onbevoegde toegang tot volledige patiëntdossiers
- Door meer data mee te geven bij bijvoorbeeld errors kan daar misbruik van gemaakt worden

**Maatregelen (NEN7510 / AVG):**
- Verplichte TLS/HTTPS voor alle API-communicatie
- Basis authenticatie
- Rolgebaseerde toegang
- Dataminimalisatie
- Audit logging

De score is hier *hoog* omdat dit invloed heeft op persoonsgegevens en medische data

### 2.2 Integriteit (Integrity) -- HOOG
De module biedt zowel lees- als schrijftoegang tot medische gegevens. Ongeautoriseerde of onbedoelde wijzigingen kunnen directe gevolgen hebben voor patiënten veiligheid.

**Bedreigingen:**
- Onbevoegde schrijftoegang kan leiden tot manipulatie van diagnoses, medicatiedoseringen of laboratoriumwaarden
- Ontbreken van invoervalidatie kan leiden tot injection-aanvallen of data-corruptie
- Gebrek aan audittrail zorgt ervoor dat wijzigingen niet herleidbaar zijn
- Race conditions bij gelijktijdige updates zorgt voor inconsistente patiëntdata

**Maatregelen (NEN7510 / AVG):**
- Strikte invoervalidatie op alle REST-endpoints
- Onveranderbaar auditlogboek
- Schrijftoegang beperken, niet iedereen kan wijzigingen maken

De reden dat de score *hoog* is komt doordat dit gaat over medische data waarbij verkeerde data kan leiden tot levensbedreiging.

### 2.3 Beschikbaarheid (Availability) -- MIDDEL-HOOG
De module dient als centrale toegangslaag voor externe applicaties. In klinische omgevingen is continue beschikbaarheid van patiëntdata essentieel.

**Bedreigingen:**
- Denial-of-Service (DoS) aanvallen op de REST-endpoints
- Overbelasting door ongelimiteerde API-calls
- Enkelvoudig storingspunt bij centrale implementatie
- Afhankelijkheid van Maven/externe dependencies

**Maatregelen (NEN7510 / AVG):**
- Rate limiting per API-gebruiker
- Monitoring en alerting op API-beschikbaarheid
- Dependency management via Dependabot

De reden dat de score hier *middel-hoog* is komt omdat het in een zorgomgeving belangrijk is dat het systeem draait en niet uitvalt