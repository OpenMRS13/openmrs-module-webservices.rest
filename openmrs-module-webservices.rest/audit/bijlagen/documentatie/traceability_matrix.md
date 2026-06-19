# Traceability Matrix NEN 7510:2024-2

Dit document toont de herleidbaarheid aan tussen de geïdentificeerde security gaps (NEN 7510:2024-2) en de daadwerkelijke verbeteringen en bewijsvoering in de OpenMRS module `webservices.rest`.

| Norm (ID) | Maatregel (Omschrijving) | Vóór (Bevinding) | Aanpassing | Na (Bewijs / Artefact) |
| :--- | :--- | :--- | :--- | :--- |
| **A.8.25** | **Beveiliging in de ontwikkelcyclus**: Implementatie van een veilige CI/CD pipeline. | **S-9**: Geen functionele pipeline aanwezig; branch protection stond uit en scans waren niet geconfigureerd. | Implementatie van GitHub Actions workflows voor build, geautomatiseerd testen, SAST, SCA en SBOM generatie. | Commit `63cc980` ("sast sca en sbom toegevoegd aan cicd pipeline"); PR #16. |
| **A.8.28** | **Veilig coderen**: Gebruik van statische analyse (SAST) om kwetsbaarheden te detecteren. | **S-2, S-3**: Ingebrachte kwetsbaarheden zoals Reflected XSS en Informatielekkage bleven onopgemerkt. | Integratie van **Snyk SAST** en **CodeQL** in de pipeline om kwetsbaarheden bij elke commit te scannen. | Commit `afb57ce` ("Create codeql.yml"); `.github/workflows/deploy.yaml` (Snyk SAST stage). |
| **A.8.8** | **Beheer van technische kwetsbaarheden**: Scannen van externe bibliotheken (SCA). | **S-7**: Kritieke verouderde componenten (Struts 1.x, Spring 5.3.x) aanwezig zonder monitoring. | Toevoegen van **Snyk SCA** en automatische generatie van een **CycloneDX SBOM** voor vulnerability tracking. | PR #16 (SCA scan); `webservices-rest-sbom.json` (Snyk scan resultaten d.d. 2026-06-03). |
| **A.8.15** | **Logregistratie**: Inrichten van een security-audittrail voor kritieke events. | **G1-G8**: Logging beperkt tot fouten; security-events (auth, PHI-inzage) werden niet of zonder context gelogd. | Introductie van de `RestAuditLog` helper; logging toegevoegd aan `AuthorizationFilter` en alle REST controllers. | Commit `faa5054` ("Add logging to module") in branch `origin/logging`; PR #35. |
| **A.5.35** | **Beoordeling van informatiebeveiliging**: Regelmatige compliance checks en gap-analyses. | Geen formele toetsing van de module tegen NEN 7510 of ISO 25010 normen beschikbaar. | Uitvoeren van een volledige security gap-analyse en het opstellen van deze Traceability Matrix. | Bestanden: `documentation/gap-analyse/security.md` en `GAP_ANALYSE_LOGGING.md`. |

---

### Ondersteunende Artefacten
- **SAST/SCA Resultaten:** In te zien via de GitHub Actions tab (Job: `Build project`).
- **Audit Logs:** Geverifieerd via `RestAuditLogTest.java` (Commit `faa5054`).
- **SBOM:** `openmrs-module-webservices.rest/webservices-rest-sbom.json`.
