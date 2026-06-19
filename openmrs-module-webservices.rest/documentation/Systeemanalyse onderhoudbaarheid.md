# Systematische Analyse van de Onderhoudbaarheid

## Inleiding en context
De onderhoudbaarheid van de `openmrs-module-webservices.rest` code is systematisch geanalyseerd met behulp van de statische analyse-tool SonarCloud. Hierbij is gekeken naar specifieke softwaremetrieken om de kwaliteit van de code op de lange termijn te waarborgen.

---

## Toegepaste Metrieken & Resultaten
Binnen SonarCloud zijn de volgende kernmetrieken geanaliseerd:

### Metriek 1: Code Smells & Maintainability Rating
* **Resultaat:** Maintainability rating: **A**
* **Uitleg:** SonarCloud deelt een rating uit op basis van de hoeveelheid 'Code Smells' (punten in de code die technisch wel werken, maar slordig zijn geschreven).
* **Bruikbaarheid:** Dit geeft direct aan hoeveel Technical Debt het project heeft. Een rating 'A' betekent dat de code efficiënt aan te passen is door nieuwe ontwikkelaars.

### Metriek 2: Duplication (Code Duplicatie)
* **Resultaat:** Duplicatie percentage: **7.6%**
* **Uitleg:** Deze metriek meet hoeveel procent van de code letterlijk is gekopieerd en geplakt.
* **Bruikbaarheid:** Hoge duplicatie maakt onderhoud lastig: als er een bug in een gekopieerd stuk code zit, moet je die namelijk op vijf plekken tegelijk oplossen. Een laag percentage (onder de 5%) toont een strakke, herbruikbare codestructuur aan.

### Metriek 3: Cyclomatic Complexity (Complexiteit)
* **Resultaat:** Aantal Cyclomatic Complexity lines: **4756**
* **Uitleg:** Dit meet het aantal unieke paden door de code (hoeveel `if`, `else`, `while` en `switch` statements er in een methode zitten).
* **Bruikbaarheid:** Hoe hoger de complexiteit, hoe moeilijker de code te begrijpen en te testen is.

---

## Bepaling en Onderbouwing van het Coverage Percentage

* **Gekozen Streefpercentage:** 70% Code Coverage op de totale codebase.

### Onderbouwing van deze keuze
De keuze voor dit percentage is gebaseerd op een weging tussen softwarekwaliteit, de aard van de applicatie en de technische haalbaarheid:

* **Het doel van de applicatie:** OpenMRS is een medisch softwaresysteem. De REST-module wisselt patiëntgegevens, diagnoses en behandelplannen uit. Een bug in deze API kan direct impact hebben op de integriteit van medische data. Een goede testdekking is daarom vereist om ervoor te zorgen dat belangrijke data-transformaties en autorisatie-checks altijd goed werken.
* **De 80%-regel in de industrie:** Binnen de software engineering is 80% coverage de algemene standaard. Hoger gaan dan 80% levert vaak weinig extra waarde op, omdat er dan onevenredig veel tijd besteed moet worden aan het testen van simpele code zoals getters en setters, in plaats van complexe bedrijfslogica.
* **Haalbaarheid:** De standaard 80% die SonarCloud adviseert is voor dit specifieke project simpelweg niet haalbaar; dat zou veel te veel tijd kosten omdat je dan bijna de hele basis moet verbouwen. Een doel van 70% op de totale module is daarentegen wel realistisch. Dit dwingt ons om kritisch te kijken en de tests alléén te schrijven voor de belangrijkste onderdelen waar de meeste risico's liggen.

### Huidige Status vs. Doelstelling
* **Huidige Code Coverage:** **65.3%**
* **Analyse:** De huidige coverage bevindt zich met 65.3% net onder de gestelde ondergrens van 70%. Dit betekent dat er op dit moment een aantal risico’s zijn waarbij ongeteste paden in de code onverwacht gedrag kunnen vertonen bij updates.
* **Actieplan:** Bij toekomstige uitbreidingen zal er strenger worden gecontroleerd op de 'Quality Gate' voor nieuwe code, zodat elke nieuwe Pull Request wél aan de 80%-norm voldoet voor dat specifieke deel en de totale score stapsgewijs omhoog wordt getrokken richting de 70%.

---

## Vastlegging en Conclusie

De resultaten uit de automatische scan laten een wisselend beeld zien:

* **Positief (Maintainability Rating A):** De algemene structuur bevat weinig zware code smells, waardoor de code snel te begrijpen is door nieuwe ontwikkelaars.
* **Aandachtspunt (Duplicatie 7.6%):** Dit is boven de industrienorm van 5%, wat betekent dat er relatief veel code is gekopieerd (bijvoorbeeld tussen verschillende API-endpoints). Dit verhoogt het risico op fouten bij toekomstig onderhoud, omdat bugfixes op meerdere plekken tegelijk moeten worden opgelost.
* **Quality Gate Status:** Op het dashboard van SonarCloud staat de status netjes op ‘Passed’. Dit komt omdat de tool eigenlijk alleen streng controleert op de nieuwe regels code die je zélf toevoegt. Omdat we de afgelopen tijd vooral aan de `deploy.yaml` en de documentatie hebben gewerkt en geen nieuwe Java-code hebben geschreven, kan er ook niks fout zijn en keurt de tool de scan goed. De oude fouten die al jaren in het project stonden (zoals de 7.6% duplicatie en de lagere testdekking van 65.3%), worden hierdoor nu niet door de scan geblokkeerd.

**Eindoordeel:** De onderhoudbaarheid krijgt op basis van de metrieken het eindoordeel **Matig tot Voldoende**. De basisstructuur is erg netjes (Rating A), maar de gekopieerde code en de net iets te lage testdekking zijn openstaande punten die in de toekomst moeten worden aangepakt.