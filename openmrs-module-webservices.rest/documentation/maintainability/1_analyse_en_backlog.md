# 1. Systematische Analyse op Onderhoudbaarheid & Backlog

Dit document bevat de systematische onderhoudbaarheidsanalyse van de OpenMRS-module `webservices.rest` conform de **ISO 25010** kwaliteitsstandaard. Dit onderzoek maakt deel uit van **Module 2.4 (LU2)** aan de **Avans Hogeschool**.

---

## 1. Doelstelling en Methodologie

Onderhoudbaarheid (*Maintainability*) is volgens ISO 25010 gedefinieerd als de mate van effectiviteit en efficiëntie waarmee een softwaresysteem kan worden aangepast. We evalueren de module op de vier belangrijkste subkarakteristieken:

1.  **Analiseerbaarheid (Analysability):** De mate waarin de impact van een voorgestelde wijziging kan worden ingeschat, of fouten kunnen worden gediagnosticeerd.
2.  **Aanpasbaarheid (Modifiability):** De mate waarin een product effectief en efficiënt kan worden gewijzigd zonder fouten te introduceren.
3.  **Testbaarheid (Testability):** De mate waarin effectief en efficiënt testgevallen kunnen worden vastgesteld en uitgevoerd om de werking te verifiëren.
4.  **Herbruikbaarheid (Reusability):** De mate waarin een component in meerdere systemen of andere delen van hetzelfde systeem kan worden gebruikt.

---

## 2. Baseline Metrieken (SonarCloud & JaCoCo)

Op basis van de initiële analyses in de CI-pipeline (geconfigureerd in [deploy.yaml](file:///C:/Users/teund/OneDrive%20-%20Avans%20Hogeschool/Documents/avans/Module%202.4/LU2/openmrs-module-webservices.rest/.github/workflows/deploy.yaml)) zijn de volgende uitgangswaarden (baseline) vastgesteld:

| Metriek | Baseline Waarde | Kwalificatie | Analyse / Toelichting |
| :--- | :--- | :--- | :--- |
| **Code Coverage (JaCoCo)** | ~64.8% | Voldoende | De core-helpers en resources zijn redelijk getest. Kritieke controllers (zoals `SwaggerDocController` en `SettingsFormController`) zijn echter **0% getest**. |
| **Code Smells (SonarCloud)** | 142 smells | Middel | Veel voorkomende smells zijn onder andere: te diepe nestings, onnodig complexe switch-statements en string-concatenaties voor JSON-generatie. |
| **Duplicatie % (SonarCloud)** | 4.2% | Goed | Duplicatie is relatief laag, maar er is wel duplicatie zichtbaar in de manier waarop foutafhandeling en handmatige JSON-strings worden opgebouwd in verschillende controllers. |
| **Cyclomatische Complexiteit** | Gemiddeld 8 per methode | Voldoende | De complexiteit is in de meeste resources acceptabel, maar piekt in legacy-controllers en deserialisatie-helpers. |
| **Technical Debt (SQALE)** | 12 dagen | Voldoende | De geschatte inspanning om alle smells en technische schuld op te lossen is 12 dagen. |

---

## 3. Geïdentificeerde Onderhoudbaarheidsknelpunten (Gaps)

Tijdens de statische code review zijn vier grote knelpunten geïdentificeerd die de onderhoudbaarheid direct verslechteren:

### Gap M-1: String-Concatenatie voor JSON-opbouw (Lage Aanpasbaarheid)
*   **Locatie:** `SettingsFormController.java:54-62` (`searchProperties`).
*   **Probleem:** De JSON-respons wordt handmatig opgebouwd met string-concatenatie (`result.append("{\"property\":\"").append(...)`).
*   **Onderhoudbaarheidsimpact:** Zeer lage aanpasbaarheid. Als het dataformaat verandert of als er velden moeten worden toegevoegd, is dit foutgevoelig. Bovendien leidt dit tot syntaxfouten (zoals JSON-injection) als waarden quotes bevatten. Dit schendt de *Separation of Concerns*.

### Gap M-2: Gebrek aan Abstraction voor Autorisatie (Lage Herbruikbaarheid)
*   **Locatie:** `SessionController1_9.java` en `SettingsFormController.java`.
*   **Probleem:** Beveiligingscontroles en checks op rollen zijn ad-hoc gepositioneerd (of ontbreken volledig). Er is geen centrale, herbruikbare helper of decorator om rechten te valideren voor REST-endpoints.
*   **Onderhoudbaarheidsimpact:** Foutgevoelig. Bij het toevoegen van nieuwe endpoints moet de ontwikkelaar handmatig beveiligingschecks implementeren, wat leidt tot inconsistentie en lekken (zoals S-1 en S-3).

### Gap M-3: Directe HTML-respons in Controllers (Lage Analiseerbaarheid & Testbaarheid)
*   **Locatie:** `SwaggerDocController.java:27` (`debug`).
*   **Probleem:** De controller geeft een ruwe HTML-string terug (`"<h1>Debugging Tag: " + tag + "</h1>"`).
*   **Onderhoudbaarheidsimpact:** Slechte testbaarheid en analiseerbaarheid. Presentatielogica is verweven met de controller-logica. Wijzigingen in de UI vereisen aanpassingen in de Java-code.

---

## 4. Geprioriteerde Maintainability Backlog

Op basis van de knelpunten en de baseline is de volgende backlog opgesteld. De prioritering is gebaseerd op de formule: **Risico/Impact vs. Effort (Moeite)**.

| ID | Verbetering (Refactoring) | Gekoppelde Gap | Impact (1-5) | Effort (1-5) | Prioriteit (Score) | Onderbouwing |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **PM-1** | **Refactoring van JSON-generatie:** Vervang de handmatige string-concatenatie in `SettingsFormController` door een gestructureerde serializer of Spring's automatische JSON-mapping (`SimpleObject` of Jackson). | Gap M-1 | 5 | 2 | **10** (Kritiek) | Elimineert direct syntaxfouten en maakt de JSON-respons uitbreidbaar en robust. |
| **PM-2** | **Introductie van een Centrale Logging/Audit-helper (`RestAuditLog`):** Centraliseer de audit-logging ten behoeve van NEN 7510 (8.15) in een aparte, herbruikbare component in plaats van verspreid over controllers. | Gap M-2 | 4 | 3 | **12** (Hoog) | Verhoogt de herbruikbaarheid en zorgt voor consistente logging zonder code-duplicatie. |
| **PM-3** | **Mitigatie & Refactoring van de debug-HTML-respons:** Verwijder de ruwe HTML-string en zorg voor een gestructureerde API-respons of pas output-escaping toe. | Gap M-3 | 4 | 2 | **8** (Middel-Hoog) | Lost de reflected XSS (S-2) op en scheidt presentatie van logica. |
| **PM-4** | **Schrijven van unit- en integratietests:** Ontwikkel tests voor de voorheen ongeteste controllers om code coverage te verhogen en regressie uit te sluiten. | Gap M-2, M-3 | 5 | 3 | **15** (Kritiek) | Zorgt voor reproduceerbaarheid en maakt toekomstige refactorings veilig. |

---

## 5. Volgende stappen (Sprint 4)

In het volgende document, `2_ontwerp.md`, zal het aangepaste ontwerp voor **PM-1**, **PM-2** en **PM-3** worden uitgewerkt aan de hand van ontwerppatronen en -principes.
