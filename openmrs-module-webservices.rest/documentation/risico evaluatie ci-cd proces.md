# Risico-evaluatie CI/CD-proces

## 1. Inleiding & Context
Dit document bevat de risico-evaluatie voor de CI/CD-pipeline van ons OpenMRS-project. Het doel van deze evaluatie is het identificeren van risico's rondom de security, kwaliteit en het proces van onze softwarelevering, en het vastleggen van maatregelen om deze risico's te beperken.

De pipeline is ingericht via GitHub Actions (`deploy.yaml`) en voert automatisch stappen uit voor de build, test en deployment van de applicatie.

### CI/CD-Inrichting

* **Naar testomgeving:** Code commit $\rightarrow$ Build $\rightarrow$ Unit tests $\rightarrow$ Security scan (SAST, SCA & SBOM) $\rightarrow$ Deploy naar testomgeving
* **Naar productieomgeving:** Code commit $\rightarrow$ Build $\rightarrow$ Unit tests $\rightarrow$ Security scan (SAST, SCA & SBOM) $\rightarrow$ Upload resultaten $\rightarrow$ Deploy naar productieomgeving

---

## 2. Risico-Matrix
Elk risico wordt beoordeeld op basis van de Kans (1-5) en de Impact (1-5).
* **Risicoscore** = Kans $\times$ Impact.
* 🟢 **Score $\le$ 7:** Acceptabel risico. Het risico moet gemonitord worden en periodiek herbeoordeeld worden.
* 🟠 **Score 8–14:** Verhoogd risico. Hier moet een mitigatieplan voor worden opgesteld met een deadline.
* 🔴 **Score $\ge$ 15:** Kritiek risico dat verplicht onmiddellijk gemitigeerd moet worden.

| ID | Risico omschrijving | Kans (1-5) | Impact (1-5) | Score | Mitigerende maatregel | Restrisico |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **R1** | **Kwetsbaarheden in packages:** Er zijn bekende beveiligingslekken in de software via externe libraries. | 3 | 4 | **12** (🟠) | Security (SAST, SCA & SBOM) is geïntegreerd in de `deploy.yaml`. De pipeline scant automatisch bij elke push en blokkeert de build bij kritieke lekken. | **Laag** |
| **R2** | **Lekken van API-keys:** Gevoelige tokens worden per ongeluk hardcoded gepusht. | 2 | 5 | **10** (🟠) | Gebruik van GitHub Secrets. De pipeline laadt deze pas tijdens runtime in. Het `.env`-bestand staat correct in `.gitignore`. | **Laag** |
| **R3** | **Defecte code naar productie:** Code pushen die syntaxfouten bevat of bestaande features van de app breekt. | 4 | 3 | **12** (🟠) | Automatische unit tests in de CI-stap. Daarnaast is **SonarCloud** gekoppeld om de code coverage te bewaken bij elke Pull Request; bij onvoldoende testdekking faalt de build. | **Laag** |
| **R4** | **Ongeteste code in main:** Een teamlid pusht onbedoeld ongeteste code rechtstreeks naar de `main` branch. | 3 | 3 | **9** (🟠) | Instellen van Branch Protection Rules op GitHub (verplichte Pull Request + review van groepsgenoot). | **Laag** |
| **R5** | **Cloud-storing tijdens demo:** De hostingpartij of GitHub Actions heeft een storing tijdens de beoordeling. | 1 | 5 | **5** (🟢) | Risico geaccepteerd vanwege zeer lage kans. Back-up: de app kan indien nodig direct lokaal gedemonstreerd worden. | **Medium** |
| **R6** | **Pipeline configuratiefout:** Aanpassingen in de `deploy.yaml` zorgen ervoor dat de pipeline faalt. | 2 | 3 | **6** (🟢) | Aanpassingen aan de pipeline eerst testen op een aparte feature branch voordat ze naar `main` gaan. | **Laag** |

---

## 3. Bow-Tie-analyse

### Bow-Tie 1: Kwetsbaarheden in packages
* **Top Event:** Er komt code met kritieke beveiligingslekken in de productie-omgeving terecht via externe libraries.
* **Threat:** Ontwikkelaar installeert een oude of onveilige package.
* **Preventive Barrier:** De security scan scant automatisch de code en packages voor kwetsbaarheden voor elke Pull Request.
* **Escalation Factor:** De GitHub Dependency Review actie draait alleen op Pull Requests. Als een ontwikkelaar met admin-rechten direct naar de branch pusht (buiten een PR om), faalt de barrière omdat de scan wordt overgeslagen.
* **Escalation Factor Barrier:** Branch Protection Rules zijn strikt ingesteld op GitHub: ook voor administrators is het onmogelijk gemaakt om direct naar `Development` of `main` te pushen zonder Pull Request.
* **Gevolg:** De applicatie wordt gehackt of data lekt uit.
* **Recovery Barrier:** GitHub Dependabot (geconfigureerd via `dependabot.yml` op de `development` branch) stuurt een geautomatiseerde Pull Request waarin het versienummer van een onveilige package aangepast wordt naar de eerstvolgende veilige versie zodra er een update is.

### Bow-Tie 2: Defecte code breekt de applicatie
* **Top Event:** De omgeving werkt niet meer na een deployment.
* **Threat:** Een groepsgenoot pusht code met een fout.
* **Preventive Barrier 1:** Unit tests worden geautomatiseerd uitgevoerd en de code coverage wordt via **SonarCloud** geanalyseerd. De kwaliteitsgrens moet behaald worden om te kunnen deployen.
* **Preventive Barrier 2:** Branch Protection Rules toepassen, waardoor code eerst gereviewd moet worden door een teamgenoot voordat er gemerged en ge-deployd kan worden.
* **Escalation Factor:** Tijdsdruk voor de deadline waardoor teamgenoten Pull Requests accepteren zonder echt naar de code te kijken.
* **Escalation Factor Barrier:** Afspraak maken in het team dat Pull Requests alleen geaccepteerd mogen worden als de code daadwerkelijk is gecontroleerd en de werking is geverifieerd.
* **Gevolg:** Applicatie is offline tijdens de beoordeling.
* **Recovery Barrier:** Git Rollback is mogelijk door commits te reverten in GitHub, waardoor de pipeline direct de laatst bekende werkende versie terugzet.

---

## 4. Conclusie
Door het vroegtijdig inrichten van de CI/CD-pipeline en het integreren van tools zoals GitHub Advanced Security (CodeQL & Dependency Review), SonarCloud en geautomatiseerde tests, zijn de grootste risico's (beveiliging en stabiliteit) effectief afgedekt. Het restrisico is hiermee acceptabel voor dit project.