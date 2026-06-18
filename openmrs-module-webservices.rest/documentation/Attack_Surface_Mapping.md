# Attack Surface Mapping: OpenMRS Web Services REST Module

Dit document bevat de Attack Surface Mapping (aanvalsoppervlak-analyse) voor de `openmrs-module-webservices.rest` module. Dit overzicht identificeert de ingangen van de module, markeert de risicovolle (high risk) componenten en analyseert de impliciete trust-relaties binnen de OpenMRS-architectuur.

---

## 1. Identificatie van Ingangen (Entry Points)
De `webservices.rest` module functioneert als de primaire RESTful API-laag voor het OpenMRS-ecosysteem. Het ontsluit de kerndiensten en data-modellen naar externe applicaties (zoals mobiele apps, frontend interfaces of externe zorgsystemen). 

De ingangen zijn onder te verdelen in de volgende categorieën:

### 1.1 HTTP REST API Eindpunten (De primaire ingang)
Het framework maakt gebruik van Spring MVC annotaties (`@Controller` / `@RequestMapping`) en een gespecialiseerd resource-concept om endpoints dynamisch te registreren onder de basis-URL: `/ws/rest/v1/` of `/ws/rest/v2/`.

* **Patiënt- en Persoonsgegevens:** `/ws/rest/v1/patient`, `/ws/rest/v1/person` (POST, GET)
* **Klinische Data:** `/ws/rest/v1/observation`, `/ws/rest/v1/encounter`, `/ws/rest/v1/order`
* **Systeem- en Gebruikersbeheer:** `/ws/rest/v1/user`, `/ws/rest/v1/role`, `/ws/rest/v1/privilege`
* **Concepten & Metadata:** `/ws/rest/v1/concept`, `/ws/rest/v1/location`, `/ws/rest/v1/provider`

### 1.2 Dynamic Search Handlers & Query Parameters
Naast de standaard CRUD-operaties op resources kent de module **Search Handlers**. Dit zijn specifieke ingangen waarmee via `GET`-requests en query-parameters (`?q=...`, `?patient=...`, `?v=...`) complexe zoeklogica binnen de database wordt getriggerd. Deze invoer beïnvloedt direct de SQL/Hibernate queries op de achtergrond.

### 1.3 Swagger API Documentatie Ingang
* **Eindpunt:** `/module/webservices/rest/apiDocs.htm` (of via de Swagger UI integratie)
* **Functie:** Deze ingang genereert automatisch documentatie over alle actieve resources en endpoints. Hoewel bedoeld voor ontwikkelaars, legt het de exacte structuur van het aanvalsoppervlak bloot aan onbevoegden indien niet goed afgeschermd.

### 1.4 Configuratie- en Administratie-interfaces
De module leest configuraties in via de OpenMRS Core globale instellingen (Global Properties) en specifieke configuratiebestanden (`config.xml`, `webModuleApplicationContext.xml`):
* `webservices.rest.allowedips`: Beperkt toegang op basis van IP (netwerkniveau-ingang).
* `webservices.rest.maxResultsAbsolute` / `maxResultsDefault`: Bepaalt datalimieten.

---

## 2. High Risk Ingangen (Hoog Risico)
De onderstaande ingangen dragen een verhoogd risico met zich mee vanwege de aard van de verwerkte gegevens (PII/PHI) of de potentiële impact op de integriteit en beschikbaarheid van het systeem.

| Ingang / Endpoint | Risicocategorie | Reden van 'High Risk' Classificatie | Mitigatie / Checkpoint |
| :--- | :--- | :--- | :--- |
| **`/ws/rest/v1/patient` & `/person`** | Privacy & Datalekken (PHI/PII) | Bevat direct herleidbare patiëntinformatie (BSN-equivalenten, NAW). Ongeautoriseerde toegang leidt direct tot een ernstig datalek conform AVG. | Vereist strikte `@Authorized` controle op privileges zoals `View Patients`. |
| **`/ws/rest/v1/user` & `/role`** | Privilege Escalation | Ingangen waarmee nieuwe gebruikers aangemaakt of rollen aangepast kunnen worden. Misbruik leidt tot volledige overname van de OpenMRS-applicatie. | Moet uitsluitend toegankelijk zijn voor de `System Administration` rol. |
| **`/ws/rest/v1/observation` (POST/PUT)** | Data Integriteit | Ingang voor het invoeren van medische waarnemingen (bloeddruk, labuitslagen). Manipulatie kan leiden tot verkeerde medische beslissingen. | Inputvalidatie op datatypen (bijv. Double conversies) en audit-logging. |
| **Search Handlers (`?q=` parameters)** | SQL/HQL Injection & DoS | Inputvelden die direct worden doorgegeven aan zoekfuncties in de database. Slecht opgebouwde zoekopdrachten kunnen leiden tot database-exhaustie (Denial of Service) of HQL-injection. | Validatie via Hibernate criteria API; `webservices.rest.maxResultsAbsolute` handhaven. |
| **`PURGE` HTTP Methoden** | Permanente Data Destructie | In tegenstelling tot `DELETE` (wat in OpenMRS vaak 'voided' of 'retired' betekent), verwijdert `PURGE` data permanent uit de database. | Moet hard beperkt worden tot super-users; bij voorkeur globaal uitschakelen in productie. |

---

## 3. Trust-analyse (Wat wordt impliciet vertrouwd?)
Binnen security-architectuur is het cruciaal om expliciet te maken wat een component *impliciet vertrouwt* zonder het zelf opnieuw te valideren. De OpenMRS REST-module steunt op de volgende trust-relaties:

### 3.1 Impliciet Vertrouwen in OpenMRS Core Security Layer
De REST-module voert zelf **geen** directe authenticatie-logica uit op database-niveau. 
* **Het vertrouwen:** De module vertrouwt erop dat OpenMRS Core de actuele sessie, Basic Auth headers of tokens correct valideert en de context vult via de `Context.getAuthenticatedUser()` API.
* **Risico:** Als er een kwetsbaarheid zit in de authenticatie-afhandeling van de Core (of een filter dat eraan voorafgaat), neemt de REST-module deze gecompromitteerde identiteit blindelings over.

### 3.2 Vertrouwen in de `@Authorized` Annotatie (AOP-Proxy)
* **Het vertrouwen:** De REST-module maakt gebruik van de `@Authorized` annotaties op serviceniveau of controllerniveau. Er wordt op vertrouwd dat Spring's Aspect-Oriented Programming (AOP) proxy's waterdicht zijn en de methode-aanroep blokkeren als de gebruiker de rechten niet bezit.
* **Risico:** Indien een developer per ongeluk een interne methode direct aanroept (binnen dezelfde klasse) in plaats van via de Spring-bean proxy, wordt de security-check omzeild (*AOP self-invocation bypass*).

### 3.3 Impliciet Vertrouwen in de Reverse Proxy / Netwerklaag
* **Het vertrouwen:** De module vertrouwt erop dat de webserver (bijv. Apache, Nginx of Tomcat) die vóór OpenMRS draait, de HTTP-headers zoals `X-Forwarded-For` niet toestaat te spoofen. Dit is kritiek omdat de module de `webservices.rest.allowedips` controleert op basis van het binnenkomende IP-adres.
* **Risico:** Als de reverse proxy niet goed is geconfigureerd, kan een aanvaller zijn IP spoofen en de IP-whitelist omzeilen.

### 3.4 Vertrouwen in Data-integriteit van Sub-modules
* **Het vertrouwen:** Wanneer via de REST API data wordt opgevraagd, vertrouwt de module erop dat de data die uit de database (via Hibernate) komt al veilig is en geen kwaadaardige JavaScript bevat.
* **Risico:** Als er via een andere weg (of oude module) opgeslagen XSS (Stored XSS) in de database is gekomen, zal de REST-module deze payload zonder her-sanitatie in JSON-formaat uitserveren naar de client.