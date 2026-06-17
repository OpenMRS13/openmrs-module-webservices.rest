# Deployment & Omgevingen (TP-omgeving)

Dit project maakt gebruik van een geautomatiseerde CI/CD-pipeline via **GitHub Actions**. We werken met een strikte scheiding tussen de **Testomgeving** en de **Productieomgeving** om de stabiliteit en veiligheid van de applicatie te garanderen.

---

## Omgevingsinrichting & Branch Strategie

De infrastructuur is ingericht als een TP-omgeving (Test & Productie). Elke omgeving is direct gekoppeld aan een specifieke Git-branch en een afgeschermde GitHub Environment.


| Omgeving | Git Branch | GitHub Environment | Doel |
| :--- | :--- | :--- | :--- |
| **Test** | `Development` | `Testomgeving` | Automatische deployment van nieuwe features voor interne controle en functionele tests. |
| **Productie** | `main` | `Productieomgeving` | De live-omgeving die door de eindgebruikers wordt bezocht. |

---

## Scheiding van Testdata en Productiedata

Om te voorkomen dat er **testdata in de productieomgeving** terechtkomt (of andersom), is er een harde scheiding aangebracht op infrastructuur- en configuratieniveau:

1. **GitHub Environments & Secrets:** Gevoelige gegevens (zoals database-wachtwoorden, API-sleutels en tokens) worden *nooit* in de code opgeslagen. Deze staan veilig in GitHub onder **Settings > Environments**.
2. **Automatische Injectie:** De GitHub Actions pipeline herkent op basis van de branch welke omgeving actief is en injecteert uitsluitend de bijbehorende *secrets*. De `Development` branch kan technisch gezien niet eens bij de productiesectrets.

---

## Hoe de Omgeving Werkt (Daily Workflow)

Volg altijd deze stappen bij het ontwikkelen van nieuwe functionaliteiten of het oplossen van bugs:

### Stap 1: Ontwikkelen & Testen (Lokaal naar Test)
1. Maak een eigen feature-branch aan vanaf `Development` (bijv. `feature/nieuwe-knop`).
2. Werk aan je code en commit je wijzigingen lokaal.
3. Maak een Pull Request (PR) aan naar de **`Development`** branch.
4. Na goedkeuring en merge triggert GitHub Actions automatisch de klus `deploy_test`. Jouw wijzigingen staan binnen enkele minuten live op de **Testserver**.

### Stap 2: Live zetten (Test naar Productie)
1. Controleer op de Testserver of de nieuwe functionaliteit volledig naar behoren werkt en of er geen bugs zijn ontstaan.
2. Werkt alles? Open dan een Pull Request van **`Development`** naar **`main`**.
3. **Branch Protection:** Er is een ruleset aanwezig waarin aangegeven staat dat er bijvoorbeeld geen directe merges/pushes kunnen zijn en dat minstens 1 iemand dit moet goedkeuren. Maar omdat we niet een betaalde versie hebben van GitHub staat dit momenteel niet
4. Zodra de PR naar `main` wordt goedgekeurd en gemerged, triggert GitHub Actions de klus `deploy_prod`. De applicatie wordt nu veilig live gezet met de productiedata.