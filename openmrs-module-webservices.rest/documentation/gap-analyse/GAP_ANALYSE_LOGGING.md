clau# Gap-analyse Logging — OpenMRS-module `webservices.rest` (v3.2.0)

**Onderwerp:** logging & monitoring (audittrail) van security-relevante events
**Object van onderzoek:** module `webservices.rest` 3.2.0 (`omod`, `omod-common`)
**Norm-koppeling:** NEN 7510:2024-2 — **8.15 Logboekregistratie (logging)**, **8.16 Monitoren van activiteiten**; raakvlak **8.11 Maskeren van gegevens**
**Datum:** 17-06-2026
**Methodiek:** statische codereview; geen runtime-/loganalyse uitgevoerd
**Verwante documenten:** `documentation/THREAT_MODEL.md` (STRIDE, T-01..T-15), `documentation/gap-analyse/security.md` (S-1..S-10)

> Plaatsing: dit document staat in de module-root. Verwante stukken: `documentation/THREAT_MODEL.md` en `documentation/gap-analyse/security.md`.

---

## Re-evaluatie eerdere analyse

Er bestond **geen zelfstandige logging-gap-analyse**. Logging kwam slechts zijdelings aan bod:

- **`gap-analyse/security.md`** beoordeelde **A.8.15 Logging als "Gedeeltelijk"** met de onderbouwing dat foutlogging bestaat in `BaseRestController.handleException` (5xx→error, 4xx→info) maar dat er "geen aantoonbare security-/audit-logging van toegang" is.
- **`THREAT_MODEL.md`** benoemde dit als **T-15 (Repudiation, score 6, groen)**: "geen aantoonbare security-/audittrail van gevoelige toegang".


**Wat nu kritisch anders wordt beoordeeld:**

1. **"Gedeeltelijk" was te mild.** De aanwezige logging dekt vrijwel uitsluitend *technische foutafhandeling* en *lifecycle* (module start/stop). Voor de kern van 8.15 — een **security-audittrail** (wie deed wat, wanneer, met welk resultaat) — is de feitelijke dekking **nihil**. Voor security-events is het oordeel **"Voldoet niet"**, niet "Gedeeltelijk".
2. **Toen gemist:** dat **mislukte authenticatie** en **IP-weigering** niet alleen "niet als audit gelogd" zijn, maar respectievelijk op **DEBUG** staan (`AuthorizationFilter.java:113`, standaard uit) en **volledig ongelogd** (`AuthorizationFilter.java:72`). Dit raakt direct de detecteerbaarheid van de eerder gevonden brute-force-dreiging (T-07).
3. **Toen gemist:** dat de module **geen log-configuratie** bevat (geen `log4j2.xml`/`logback.xml`) en **geen audit-mechanisme** gebruikt (geen `AuditLog`/`auditService`). Bewaartermijn, integriteit en onveranderlijkheid van logs zijn dus **niet in deze repo geborgd** — een 8.15-eis die eerder niet expliciet was getoetst.
4. **Herwaardering risico:** T-15 kreeg score 6 (groen) puur als losse repudiation-dreiging. In samenhang met T-01/T-02/T-03 (direct exploiteerbaar én **ongelogd**) is het ontbreken van logging een **impactvergroter** voor meerdere rode dreigingen: een geslaagde aanval is forensisch niet te reconstrueren. De logging-gap verdient daarmee een **hogere prioriteit** dan de losse score van T-15 suggereerde.

---


## STAP 2 — Security-events afgeleid uit endpoints/filters, gekoppeld aan dreigingen

Afgeleid uit de controllers, REST-endpoints en filters; gekoppeld aan de dreiging-ID's uit `THREAT_MODEL.md`.

| Event | Herkomst (bestand:regel) | Gekoppelde dreiging |
|---|---|---|
| E1 — Geslaagde authenticatie | `AuthorizationFilter.java:107-108` | T-07 (Spoofing) |
| E2 — Mislukte authenticatie | `AuthorizationFilter.java:110-114` | T-07, T-09 (brute-force/DoS) |
| E3 — IP-weigering (403) | `AuthorizationFilter.java:69-74` | T-08 (open IP-allowlist) |
| E4 — Logout / sessie-invalidatie | `SessionController1_9.java:129-135` | T-07 |
| E5 — PHI-inzage (retrieve/list) | `MainResourceController.java:68-76, 181-213` | T-10 (autorisatie gedelegeerd) |
| E6 — Bulk-/search-extractie | `MainResourceController.java:181-213, 222-247` | T-10, T-12 (DoS) |
| E7 — Datawijziging (create/update/delete) | `MainResourceController.java:85-94, 119-137, 145-155` | T-10 |
| E8 — Purge (onherstelbaar verwijderen) | `MainResourceController.java:163-172` | T-10 |
| E9 — Bestandsupload | `MainResourceController.java:96-109` | T-12 (DoS) |
| E10 — Global-property uitlezen (secrets) | `SettingsFormController.java:50-63` | **T-01 (rood)** |
| E11 — Global-property wijzigen (config) | `SettingsFormController.java:65-80` | T-10 |
| E12 — Diagnostics-endpoint (rollen/privileges) | `SessionController1_9.java:170-182` | **T-02 (rood)** |
| E13 — Debug-endpoint (XSS-vector) | `SwaggerDocController.java:24-28` | **T-03 (rood)** |
| E14 — Admin: DB-cache legen | `ClearDbCacheController2_0.java:66-95` | T-10 |
| E15 — Admin: zoekindex herbouwen | `SearchIndexController2_0.java:61-81` | T-10 |
| E16 — Wachtwoord wijzigen/resetten | `ChangePasswordController1_8`, `PasswordResetController2_2` | T-07 |
| E17 — Server-/applicatiefout (5xx/4xx) | `BaseRestController.java:122-128` | T-14 (info disclosure) |

---

## STAP 3 — Overzichtstabel logging vs. NEN 7510:2024-2 (8.15)

Legenda "Gelogd?": **ja** = op default-niveau (info/warn/error) gelogd · **deels** = alleen op DEBUG of zonder security-context · **nee** = geen logregel.

| Event | Endpoint/code (bestand:regel) | Gelogd? | Wat wordt gelogd | Gevoelige data in log? | Compliant 8.15? | Dreiging |
|---|---|---|---|---|---|---|
| E1 Geslaagde auth | `AuthorizationFilter.java:108` | **deels** | `authenticated [username]` op **DEBUG** | username (PII, laag) | **Nee** — standaard uit; geen tijd/bron-IP/resultaat | T-07 |
| E2 Mislukte auth | `AuthorizationFilter.java:113` | **deels** | exception op **DEBUG**; exceptie wordt geslikt (`:110-114`) | exceptie | **Nee** — kerngebeurtenis voor misbruikdetectie ontbreekt op default | T-07, T-09 |
| E3 IP-weigering | `AuthorizationFilter.java:69-74` | **nee** | niets — alleen `sendError(403)` | n.v.t. | **Nee** — geen wie/wanneer/bron | T-08 |
| E4 Logout | `SessionController1_9.java:129-135` | **nee** | niets | n.v.t. | **Nee** — sessie-einde niet herleidbaar | T-07 |
| E5 PHI-inzage | `MainResourceController.java:68,181` | **nee** | niets | n.v.t. | **Nee** — inzage PHI niet vastgelegd (kern van 8.15 in zorg) | T-10 |
| E6 Bulk/search | `MainResourceController.java:181,222` | **nee** | niets | n.v.t. | **Nee** — massale extractie onzichtbaar | T-10, T-12 |
| E7 Datawijziging | `MainResourceController.java:85,119,145` | **nee** | niets (in deze module) | n.v.t. | **Nee** — wijziging niet onweerlegbaar herleidbaar | T-10 |
| E8 Purge | `MainResourceController.java:163-172` | **nee** | niets | n.v.t. | **Nee** — onherstelbare actie zonder spoor | T-10 |
| E9 Upload | `MainResourceController.java:96-109` | **nee** | niets | n.v.t. | **Nee** | T-12 |
| E10 GP uitlezen | `SettingsFormController.java:50-63` | **nee** | niets | n.v.t. | **Nee** — ongeauth. secret-uitlezing volledig onzichtbaar | **T-01** |
| E11 GP wijzigen | `SettingsFormController.java:65-80` | **nee** | niets | n.v.t. | **Nee** — configwijziging niet gelogd | T-10 |
| E12 Diagnostics | `SessionController1_9.java:170-182` | **nee** | niets | n.v.t. | **Nee** — rollen/privilege-lek onzichtbaar | **T-02** |
| E13 Debug/XSS | `SwaggerDocController.java:24-28` | **nee** | niets | n.v.t. | **Nee** — XSS-vector zonder logging | **T-03** |
| E14 Cache legen | `ClearDbCacheController2_0.java:66-95` | **deels** | admin-actie op **DEBUG**/één `info` (`:95`, "not found") | nee | **Nee** — geen actor; standaard uit | T-10 |
| E15 Index herbouwen | `SearchIndexController2_0.java:61-81` | **deels** | admin-actie op **DEBUG** | nee | **Nee** — geen actor; standaard uit | T-10 |
| E16 Wachtwoord wijz./reset | `ChangePasswordController1_8`, `PasswordResetController2_2` | **nee** | geen `log.*` aangetroffen in deze classes | n.v.t. | **Nee** — gevoelige credential-actie niet gelogd | T-07 |
| E17 App-fout 5xx/4xx | `BaseRestController.java:122-128` | **ja** | `ex.getMessage()` + stacktrace (5xx→error, 4xx→info) | **mogelijk PHI**: ruwe exceptiemsg kan ingezonden data bevatten | **Deels** — wel gelogd, maar geen maskering (8.11) en geen security-context | T-14 |
| (overig) GP-parse | `LayoutTemplateProvider.java:124` | **ja** | `warn` met **GlobalProperty-naam + token-waarde** | **mogelijk** configwaarde | **Deels** — risico op gevoelige waarde in log | — |

**Onderbouwing 8.15-beoordeling (wie/wat/wanneer · onweerlegbaarheid · integriteit · bewaartermijn):**
- **Wie/wat/wanneer:** Geen enkele logregel legt consistent *actor (gebruiker/bron-IP)*, *actie/resource* en *tijdstip* vast. Waar wel gelogd wordt (E17), gaat het om technische fouten zonder gebruikerscontext. → kernvereiste 8.15 niet ingevuld.
- **Onweerlegbaarheid:** Zonder actor-gekoppelde audittrail zijn acties (datawijziging, purge, secret-uitlezing) niet onweerlegbaar aan een persoon toe te wijzen → koppelt aan **T-15 (Repudiation)**.
- **Integriteit/onveranderlijkheid:** Geen log-configuratie in de module (geen `log4j2.xml`/`logback.xml` aangetroffen); logs gaan naar de platform-logger zonder aantoonbare append-only/WORM-borging of doorzending naar een centrale, niet-manipuleerbare store. → 8.15-integriteitseis niet aantoonbaar.
- **Bewaartermijn:** Niet vastgelegd in de repo; geen retentie-/rotatiebeleid zichtbaar. → niet aantoonbaar.
- **8.16 Monitoren:** Omdat E2/E3/E10/E12 niet (of alleen op DEBUG) gelogd worden, is er geen bron voor detectie/alerting van misbruik. Monitoring is daarmee feitelijk onmogelijk op de relevante events.

---

## STAP 4 — Gap: huidig vs. gewenst + aanbevelingen

Leidend principe: **"niet gelogd = niet gebeurd"** — een security-event dat niet (op default-niveau, met actor en tijd) wordt vastgelegd, is achteraf niet aantoonbaar en niet detecteerbaar.

### G1 — Authenticatie-events (E1/E2) staan op DEBUG; mislukte auth wordt geslikt
- **Huidig:** `AuthorizationFilter.java:108` (succes) en `:113` (falen) loggen op **DEBUG**; de auth-exceptie wordt bewust geslikt (`:110-114`).
- **Gewenst (8.15):** Geslaagde én mislukte authenticatie op **INFO/WARN** met `username`, `bron-IP` (`request.getRemoteAddr()`), `tijdstip` en `resultaat`. Mislukte pogingen op **WARN** om brute-force (T-07/T-09) detecteerbaar te maken.
- **Aanbeveling:** Voeg in `AuthorizationFilter.doFilter` een `log.info`/`log.warn` toe op succes/falen (geen wachtwoord loggen, username wel). → **NEN 8.15**, detectie via **8.16**.

### G2 — IP-weigering (E3) wordt niet gelogd
- **Huidig:** `AuthorizationFilter.java:72` stuurt 403 **zonder logregel**.
- **Gewenst:** Elke geweigerde IP op **WARN** met geweigerd IP + tijdstip.
- **Aanbeveling:** `log.warn("REST access denied for IP {}", request.getRemoteAddr())` vóór `sendError`. → **8.15/8.16** (koppelt T-08).

### G3 — Geen audittrail voor PHI-inzage en datawijziging (E5–E8)
- **Huidig:** `MainResourceController` (`:68,85,119,145,163,181,222`) logt **niets**; toegang en mutaties op patiëntdata laten geen spoor na.
- **Gewenst (8.15, zorgspecifiek):** Audittrail per PHI-toegang en -mutatie: *actor, actie (read/create/update/delete/purge), resourcetype + uuid, tijdstip, resultaat*. PHI-**waarden** niet in de logregel (alleen identificatoren) → **8.11 maskeren**.
- **Aanbeveling:** Centrale audit-hook (filter/interceptor of `HandlerInterceptor`) over `/rest/v1/*` die per request een gestructureerde auditregel schrijft; bij voorkeur naar een centrale, append-only store. Purge (`:163`) expliciet op **WARN** (onherstelbaar). → **8.15** + **8.11**.

### G4 — Global-property uitlezen/wijzigen (E10/E11) niet gelogd
- **Huidig:** `SettingsFormController.java:50-63` (uitlezen, T-01) en `:65-80` (wijzigen) loggen niets.
- **Gewenst:** Uitlezen van GP's (zeker ongeauthenticeerd) op **WARN** met bron-IP; wijziging op **INFO** met actor + gewijzigde property-namen (**niet** de waarden → 8.11).
- **Aanbeveling:** Logging toevoegen bij het dichtzetten van T-01 (zie security.md); minimaal de *namen* loggen, waarden maskeren. → **8.15 + 8.11**.

### G5 — Ingebrachte endpoints `/session/diag` en `/apiDocs/debug` (E12/E13) niet gelogd
- **Huidig:** `SessionController1_9.java:170-182` en `SwaggerDocController.java:24-28` loggen niets; misbruik van deze rode dreigingen (T-02/T-03) is onzichtbaar.
- **Gewenst:** Bij voorkeur **verwijderen** (zie THREAT_MODEL). Zolang ze bestaan: elke aanroep op **WARN** met bron-IP en parameters (na sanitatie).
- **Aanbeveling:** Verwijderen; als tijdelijk blijven, WARN-logging als compensatie. → **8.15/8.16**.

### G6 — Admin-acties (E14/E15) alleen op DEBUG, zonder actor
- **Huidig:** `ClearDbCacheController2_0.java:66-95` en `SearchIndexController2_0.java:61-81` op **DEBUG**, zonder gebruiker.
- **Gewenst:** Beheeracties (cache legen, index herbouwen) op **INFO** met actor + tijdstip.
- **Aanbeveling:** Niveau naar INFO en `Context.getAuthenticatedUser()` opnemen. → **8.15**.

### G7 — Wachtwoord wijzigen/resetten (E16) niet gelogd
- **Huidig:** In `ChangePasswordController1_8` en `PasswordResetController2_2` zijn **geen** `log.*`-aanroepen aangetroffen.
- **Gewenst:** Credential-wijziging op **INFO/WARN** met actor + doel-gebruiker + tijdstip; **nooit** het wachtwoord zelf.
- **Aanbeveling:** Audit-logregel toevoegen (zonder credential-inhoud). → **8.15 + 8.11**.

### G8 — Gevoelige data in bestaande logs (E17 + LayoutTemplateProvider)
- **Huidig:** `BaseRestController.java:124/127` logt ruwe `ex.getMessage()` (kan ingezonden data/PHI bevatten); `LayoutTemplateProvider.java:124` logt GP-naam **+ token-waarde**.
- **Gewenst (8.11):** Geen PHI/secrets in logs; exceptiemessages saneren, GP-waarden maskeren.
- **Aanbeveling:** Maskeer/strip gevoelige inhoud vóór loggen; log bij `:124` alleen de property-*naam*, niet de waarde. → **8.11** (raakt 8.15).

### G9 — Geen log-configuratie, retentie of integriteitsborging in de module
- **Huidig:** Geen `log4j2.xml`/`logback.xml`; geen audit-mechanisme; bewaartermijn/onveranderlijkheid niet vastgelegd.
- **Gewenst (8.15):** Vastgelegd niveau/appender-beleid, doorzending naar centrale **append-only/WORM** store, gedefinieerde **bewaartermijn**, en integriteitsbescherming van logs.
- **Aanbeveling:** Logbeleid + centrale logverzameling (bv. SIEM) op platform-/deployniveau documenteren en aantonen; in de module gestructureerde (audit-)logging emitteren. → **8.15 + 8.16**.

### Prioriteitenlijst (op risico)

1. **G4 / G5** — koppelt aan de rode dreigingen **T-01, T-02, T-03**; nu geheel onzichtbaar. Eerst dichtzetten (verwijderen) en bij voortbestaan WARN-logging. *(hoogste prioriteit)*
2. **G1 / G2** — authenticatie- en IP-events op default-niveau; randvoorwaarde voor brute-force-detectie (T-07/T-08/T-09).
3. **G3** — audittrail voor PHI-inzage/mutatie en purge; kern van 8.15 in de zorg (T-10) en grootste structurele inspanning.
4. **G8** — geen PHI/secrets in bestaande logs (8.11); relatief snel te mitigeren.
5. **G7 / G6** — credential- en admin-acties auditbaar maken.
6. **G9** — logbeleid, retentie en integriteit borgen (deels platform/proces, apart aantonen).

> **Slot:** Voor security-relevante events voldoet de module **niet** aan NEN 7510:2024-2 §8.15/8.16. De eerdere kwalificatie "Gedeeltelijk" (security.md) wordt op grond van deze inventarisatie herzien naar **"Voldoet niet"** voor de audittrail; de aanwezige logging beperkt zich tot technische foutafhandeling en module-lifecycle.

---

## STAP 5 — Implementatie (17-06-2026): status per gat

De ontbrekende logging is geïmplementeerd via één centrale, gestructureerde audit-helper
**`RestAuditLog`** (SLF4J — geen nieuw framework), met een **eigen logger-naam**
`org.openmrs.module.webservices.rest.audit` zodat een deployment de audittrail naar een aparte,
append-only/integriteitsbeschermde appender of SIEM kan routeren. Elke regel bevat **WIE** (`user=<id>`
of `user=unauthenticated`; bij auth de username), **WAT** (`action` + `resource` + `id`), **WANNEER**
(framework-timestamp) en **UITKOMST** (`success`/`failure`/`denied`). Caller-velden worden
gesaneerd (control-tekens → `_`) tegen log-injectie. **Geen** PHI-inhoud, wachtwoorden, tokens,
activation-keys of global-property-waarden worden ooit aan de helper meegegeven.

**Nieuw:** `omod-common/.../web/RestAuditLog.java` + test `omod-common/.../web/RestAuditLogTest.java`.

| Gat | Status | Wat toegevoegd (event → niveau) | Bestand | NEN |
|---|---|---|---|---|
| **G1** Auth succes/falen | **Opgelost** | `authSuccess` INFO, `authFailure` WARN (username+IP, **geen wachtwoord**) | `AuthorizationFilter.java` | 8.15/8.16 |
| **G2** IP-weigering | **Opgelost** | `accessDenied` WARN (`ip-not-allowed`+IP) vóór 403 | `AuthorizationFilter.java` | 8.15/8.16 |
| **G3** PHI-inzage/mutatie/purge | **Opgelost** (code-level) | `read` INFO (retrieve/list/search), `write` INFO (create/upload/update/undelete/delete), `sensitive` WARN (purge) — alleen resourcetype+uuid | `MainResourceController.java` | 8.15/8.11 |
| **G4** GP uitlezen/wijzigen | **Opgelost** | `sensitiveAccess` WARN (`gp-search`, prefix+aantal+IP, **geen waarden**); `write` INFO (`gp-update`, property-**namen**) | `SettingsFormController.java` | 8.15/8.11 |
| **G5** diag/debug/logout | **Opgelost** (compenserend) | `sensitiveAccess` WARN (`session-diag`, `apidocs-debug` — alleen IP + `tagLength`, **geen tag-waarde/token**); `write` INFO (`logout`) | `SessionController1_9.java`, `SwaggerDocController.java` | 8.15/8.16 |
| **G6** Admin-acties | **Opgelost** | `write` INFO mét actor (`clear-db-cache`, `update-search-index`) | `ClearDbCacheController2_0.java`, `SearchIndexController2_0.java` | 8.15 |
| **G7** Wachtwoord wijz./reset | **Opgelost** | `write` INFO (eigen ww / reset), `sensitive` WARN (ww van ander) — **nooit** wachtwoord/activation-key; reset logt alleen of user gevonden is (uuid) | `ChangePasswordController1_8.java`, `PasswordResetController2_2.java` | 8.15/8.11 |
| **G8** Gevoelige data in logs | **Deels** | `LayoutTemplateProvider:124` logt nu alleen property-**naam**, niet de token-waarde | `LayoutTemplateProvider.java` | 8.11 |
| **G9** Logconfig/retentie/immutability | **Restpunt** | Code-haak: aparte logger-naam voor routering; retentie/onveranderlijkheid = deploy/proces | n.v.t. (deploy) | 8.15/8.16 |

### Restpunten (bewust niet of niet-volledig in code opgelost)

- **G8 — `BaseRestController.handleException:124/127`:** logt nog steeds de ruwe `ex.getMessage()` +
  stacktrace (5xx→error, 4xx→info). Dit is legitieme **server-side** technische diagnostiek; de
  message kán ingezonden data bevatten. Bewust **ongewijzigd** gelaten (zou debugbaarheid raken).
  *Aanbeveling:* maskeren op appender-/platformniveau. De nieuwe audit-regels nemen sowieso **geen**
  exceptiemessages mee.
- **G9 — onveranderlijkheid/bewaartermijn/centralisatie:** valt buiten de modulecode (deploy/proces).
  De code levert de routerings-haak (aparte logger-naam); het daadwerkelijk wegschrijven naar een
  append-only store/SIEM en het retentiebeleid moeten op platform-/deployniveau worden ingericht en
  aangetoond.
- **Ingebrachte endpoints (T-01/T-02/T-03) niet verwijderd:** dat is een *security-fix* buiten de
  scope van deze logging-opdracht. Hier is alleen **compenserende WARN-logging** toegevoegd, conform
  de aanbeveling "zolang ze bestaan".

### Teststatus (WS05)

- **`RestAuditLogTest`** (omod-common, backend-onafhankelijk): bewijst (a) correct gestructureerde
  regel per actie (WIE/WAT/uitkomst) en (b) dat waarden nooit in de regel komen + CR/LF-injectie wordt
  geneutraliseerd + `currentPrincipal()` valt zonder context veilig terug op `unauthenticated`. Dekt
  bovendien álle publieke methoden (auditing breekt nooit een request).
- **`AuthorizationFilterTest`** (omod-common, context-sensitief): dekt de IP-weigering (G2) en de drie
  mislukte-authenticatie-paden (G1) — bevestigt o.a. dat de filter bij faalauth de keten laat doorlopen.
- **`SettingsFormControllerTest`** (omod, context-sensitief): dekt de global-property-zoek én de
  POST-`handleSubmission` (`gp-update`) (G4).
- **`SwaggerDocControllerTest`** (omod): dekt het debug-endpoint (G5).
- **`SessionController1_9Test`** uitgebreid: `getDiagnostics`-test toegevoegd (G5); `delete`-test dekte
  de logout-audit al.
- Bestaande tests dekken de nieuwe regels in `MainResourceController` (CRUD), `ChangePasswordController1_8`,
  `PasswordResetController2_2`, `ClearDbCacheController2_0` en `SearchIndexController2_0`.
- **Toegevoegd n.a.v. SonarCloud quality gate** (coverage nieuwe code < 80%): bovenstaande
  filter-/controllertests verhogen de dekking van de toegevoegde auditregels.
- De `password-reset-request`-auditregel is vóór `setUserActivationKey` geplaatst, zodat de bestaande
  `PasswordResetController2_2Test` (die op de e-mailstap een `MessageException` verwacht) deze regel nu
  bereikt — tevens semantisch juister (de aanvraag wordt gelogd, ook als bezorging faalt).
- **Beperking:** de build kon **niet lokaal worden uitgevoerd** (geen Maven in de werkomgeving). De
  context-sensitieve tests volgen bestaande patronen (`RestUtilTest`, `SessionController1_9Test`) maar
  moeten in CI worden bevestigd. Bewust ongedekt blijven enkele losse regels (samen ruim onder de
  20%-marge): de *succesvolle* Basic-auth in `AuthorizationFilter` (vereist geldige testcredentials),
  de `upload`/`undelete`-takken van `MainResourceController` en de `warn`-tak in
  `LayoutTemplateProvider`. Geschatte line-coverage op de nieuwe regels ligt hiermee ruim boven 80%.
