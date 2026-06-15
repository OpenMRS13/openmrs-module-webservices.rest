# Gap-analyse Deel 1 – Onderhoudbaarheid

**Object van onderzoek:** OpenMRS-module `webservices.rest` (versie 3.2.0)
**Repository:** OpenMRS13/openmrs-module-webservices.rest
**Branch t.t.v. analyse:** `Development`
**Datum:** 11-06-2026
**Auteur(s):** Gap-analyse-team (schoolopdracht)
**Status:** concept – geschikt als auditbijlage

---

## 1. Context en samenvatting

### 1.1 Doel en module
De module stelt de OpenMRS-kern-API beschikbaar als REST-webservices. Andere
applicaties kunnen er medische gegevens (patiënten, encounters, observaties,
concepten enz.) mee opvragen en wegschrijven. De module draait *in* een OpenMRS-
platforminstantie en is dus geen losstaande applicatie.

### 1.2 Modulestructuur (Maven multi-module)
| Module | Verantwoordelijkheid | Java-bestanden (main / test) |
| :--- | :--- | :--- |
| `omod-common` | Herbruikbare kern: resource-framework, conversie, Swagger-generatie, utilities | 124 / 34 |
| `omod` | Concrete REST-resources en controllers per OpenMRS-versie (`openmrs1_8` … `openmrs2_8`) | 221 / 290 |
| `integration-tests` | End-to-end tests met Rest-Assured tegen een draaiende server | 0 / 2 |

**Omvang (gemeten):** 345 main-bestanden / **44.110 regels** productiecode;
326 test-bestanden / **38.553 regels** testcode. Bron: telling met script over
`**/src/main/java` resp. `**/src/test/java`.

### 1.3 Frameworks en technische stack
- **Spring Framework** (MVC-controllers, DI) – versie 5.3.30 (transitief via platform).
- **Hibernate ORM** 5.6.x en **Hibernate Search** 6.2.x (transitief).
- **Jackson** (JSON) en **jackson-dataformat-yaml** 2.13.3 (direct gedeclareerd in `omod`).
- **Swagger Core** 1.6.2 (direct in `omod-common`) voor API-documentatiegeneratie.
- **JUnit 4** (dominant) + **JUnit 5 / Jupiter** (gedeeltelijke migratie) + **Mockito** 3.12.4.
- **Rest-Assured** voor integratietests.

### 1.4 Java-versie (belangrijke observatie)
`pom.xml` zet `maven.compiler.source`/`target` op **1.8** (Java 8) en de `README`
schrijft Java 8 voor. De analyse-omgeving draait echter op **Temurin JDK 17**.
De broncode wordt dus op een verouderd taalniveau (Java 8) vastgepind terwijl de
runtime nieuwer is. Dit is een onderhoudbaarheidsrisico (zie gap O-8).

### 1.5 Architectuurpatroon
De module gebruikt een **template-/delegation-patroon**: `BaseDelegatingResource`
en `DelegatingCrudResource` bevatten generiek CRUD-gedrag; per domeinobject en
per OpenMRS-versie is er een concrete subklasse (`PatientResource1_8`,
`ConceptResource1_8`, …). Versieverschillen worden opgevangen via
versie-gesuffixte klassen die overerven van een eerdere versie. Dit is een
bewuste, schaalbare opzet, maar leidt tot **veel bijna-identieke klassen** en een
sterke afhankelijkheid van overerving (zie code smells).

---

## 2. Methodologie en beperkingen

- **Statische, handmatige review** van de broncode, aangevuld met scripts voor
  metingen (regeltellingen, methodelengte, geneste-conditie-telling).
- **Cyclomatische complexiteit (cc)** is **heuristisch** bepaald (regex-telling van
  `if/for/while/case/catch/&&/||`). De waarden zijn **indicatief**, niet exact; ze
  dienen om uitschieters te prioriteren, niet als auditmeetwaarde.
- **`mvn` was niet beschikbaar** op de analysemachine, en gespecialiseerde
  tooling (PMD, Checkstyle, SonarQube, JaCoCo-rapport) is **niet uitgevoerd**. De
  voorgestelde NFR-drempels (§4) zijn daarom richtwaarden die in CI nog
  geijkt/gevalideerd moeten worden tegen een echte meting.
- Waar relevant onderscheiden we **eigen modulecode** van **upstream OpenMRS-code**
  (de module is een fork; sommige smells zijn overgenomen, andere lijken bewust
  toegevoegd voor deze opdracht).

---

## 3. Onderhoudbaarheidsanalyse

### 3.1 Grootste en complexste klassen (god-class-kandidaten)

| Klasse | Regels | #Methoden | Observatie |
| :--- | ---: | ---: | :--- |
| `SwaggerSpecificationCreator` | 1.240 | 33 | Genereert de volledige OpenAPI-spec; combineert reflectie, model-opbouw, path-opbouw en string-manipulatie in één klasse. Duidelijke **God Class**. |
| `RestUtil` | 950 | 26 | Grab-bag van statische helpers (IP-matching, classpath-scanning, response-opbouw, foutafhandeling). Lage cohesie (**utility-class smell**). |
| `BaseDelegatingResource` | 901 | 38 | Centrale basisklasse van het resource-framework; zeer breed verantwoordelijkheidsgebied. |
| `RestServiceImpl` | 737 | 31 | Service-laag die resources/handlers registreert en resolvet. |
| `ConceptResource1_8` | 716 | 37 | Grootste concrete resource; veel domeinlogica + Swagger-modellen. |
| `ConversionUtil` | 592 | – | Generieke type-conversie; bevat de complexste methode (zie 3.2). |

Locaties: `omod-common/.../docs/swagger/SwaggerSpecificationCreator.java`,
`omod-common/.../rest/web/RestUtil.java`,
`omod-common/.../resource/impl/BaseDelegatingResource.java`,
`omod-common/.../api/impl/RestServiceImpl.java`,
`omod/.../resource/openmrs1_8/ConceptResource1_8.java`,
`omod-common/.../rest/web/ConversionUtil.java`.

### 3.2 Langste en complexste methoden (indicatief)

| Methode | Locatie | Regels | cc (heuristisch) |
| :--- | :--- | ---: | ---: |
| `testOperationImplemented(...)` | `SwaggerSpecificationCreator.java:246` | 171 | ~37 |
| `setValue(Obs, Object)` | `ObsResource1_8.java:406` | 118 | ~40 |
| `convert(Object, Type)` | `ConversionUtil.java:176` | 118 | ~40 |
| `search(RequestContext)` | `OrderSearchHandler2_3.java:127` | 123 | ~18 |
| `search(RequestContext)` | `ConceptSearchHandler1_8.java:74` | 115 | ~28 |
| `getClassesForPackage(String)` | `RestUtil.java:718` | 94 | ~22 |
| `search(RequestContext)` | `RelationshipSearchHandler1_8.java:65` | 72 | ~25 |
| `getSearchHandler(...)` | `RestServiceImpl.java:532` | 71 | ~19 |

**Interpretatie:** methoden met cc ≳ 20 en/of > 100 regels zijn zwaar te testen,
te begrijpen en te wijzigen. `ObsResource1_8.setValue` (`:406`) en
`ConversionUtil.convert` (`:176`) springen eruit met cc ≈ 40: beide zijn lange
`if/else`-cascades die op runtime-type vertakken — klassieke kandidaten voor
*Replace Conditional with Polymorphism* / *Strategy* (zie §5).

### 3.3 Code smells

**a) Duplicatie – `*SearchHandler`-familie.**
Er zijn **19 `…SearchHandler`-klassen** in `omod/src/main`. Hun `search(RequestContext)`-
methoden volgen vrijwel hetzelfde stramien (parameters uitlezen → valideren →
service aanroepen → `NeedsPaging`/`AlreadyPaged` teruggeven) met cc 12–28 per stuk.
Veel van die logica (parameter-extractie, paginering, lege-resultaat-afhandeling)
is herhaald i.p.v. geabstraheerd. Risico: een bugfix moet op ~19 plaatsen worden
herhaald.

**b) God classes / lage cohesie.** Zie 3.1 – met name `SwaggerSpecificationCreator`
en `RestUtil` schenden het **Single Responsibility Principle**.

**c) Dode/decoy-code.**
- `SessionController1_9.getDiagnostics` (`:172`) declareert een parameter `token`
  die **nergens** wordt gebruikt (schijn-autorisatie). Dode parameter én
  beveiligingsprobleem (zie security.md, bevinding S-1).
- Talrijke `//FIXME`-markeringen in de Swagger-modelmethoden van resources
  (o.a. `ConceptResource1_8.java:231-235`, `EncounterResource1_8.java:102-110`,
  `CohortResource1_8.java:103/113`): bekende, onafgemaakte schema-definities.

**d) Magic values / strings.**
- `ObsResource1_8.setValue` (`:500-501`) bevat hardgecodeerde lijsten
  `("true","1","on","yes")` / `("false","0","off","no")` midden in de logica.
- Boolean-vlaggen en speciale gevallen (complex obs, coded, location) worden via
  inline-strings en `instanceof`-checks afgehandeld i.p.v. via benoemde constanten
  of types.

**e) Onnauwkeurige foutafhandeling.**
- `ChangePasswordController1_8.changeOthersPassword` (`:81`) gooit een **kale
  `new NullPointerException()`** om "niet gevonden" te signaleren, die vervolgens
  via een `@ExceptionHandler(NullPointerException.class)` wordt omgezet naar 404.
  NPE als controle-flow is een anti-patroon (slechte leesbaarheid, verbergt echte
  NPE's).
- Lege `catch (Exception ex) {}`-blokken in `SettingsFormController` (`:151`, `:160`)
  onderdrukken validatiefouten stil.

**f) SOLID-observaties.**
- **SRP:** geschonden door de god classes (3.1) en door resources die zowel
  domeinmapping als Swagger-schema's bevatten.
- **OCP/LSP:** de versie-overerving (`…2_3 extends …2_2 extends …`) is gevoelig
  voor LSP-spanning: subklassen overschrijven gedrag deels en zetten soms
  bestaande properties terug, wat moeilijk te volgen is.
- **DIP:** veel code roept `Context.getXxxService()` (statische service-locator)
  direct aan i.p.v. geïnjecteerde dependencies — dit is OpenMRS-conventie maar
  bemoeilijkt unit-testen (zie 3.4).

**g) Naamgeving.** Overwegend redelijk en consistent (domeingedreven). Minpunten:
generieke namen als `RestUtil`/`ConversionUtil` (verzamelnaam-smell) en
versie-suffixen in klassenamen die de werkelijke functionele verschillen niet
zichtbaar maken.

### 3.4 Teststructuur en dekking

**Soorten tests:**
- **Controller-tests** (`…ControllerTest`, leeuwendeel) draaien tegen een
  in-memory OpenMRS-context met testdatasets (XML) – feitelijk *integratie-achtige*
  tests, geen pure unit-tests.
- **Resource-tests** per domeinobject.
- **Echte integratietests** (Rest-Assured): **slechts 2 bestanden**
  (`integration-tests/.../ITBase.java`, `SessionIT.java`).

**Frameworkconsistentie:** **166** testbestanden gebruiken nog JUnit 4
(`import org.junit.Test`) tegen **6** op JUnit 5 (Jupiter). De migratie is dus
halverwege blijven steken → inconsistente test-API's en dubbele runners.

**Dekking – kwalitatieve inschatting (geen JaCoCo-rapport gedraaid):**
- De ratio testcode/productiecode is gezond (≈ 0,87:1) en de meeste resources en
  controllers hebben een bijbehorende testklasse → de *breedte* van de dekking
  lijkt redelijk.
- **Kritieke ongeteste onderdelen:** de (vermoedelijk voor deze opdracht
  toegevoegde) endpoints hebben **geen enkele test**:
  - `SessionController1_9.getDiagnostics` (`/session/diag`) – geen test.
  - `SwaggerDocController.debug` (`/apiDocs/debug`) – geen test.
  - `SettingsFormController.searchProperties` (`/settings.form/search`) – geen test.
  Deze zijn juist het meest risicovol (zie security.md).
- De complexste methoden (`ObsResource1_8.setValue`, `ConversionUtil.convert`,
  `SwaggerSpecificationCreator.testOperationImplemented`) zijn door hun cc ≈ 40
  vrijwel zeker **niet padgedekt**; voor zulke methoden is volledige branch-dekking
  zonder refactoring nauwelijks haalbaar.

> **Aanname:** zonder JaCoCo-rapport zijn dekkingspercentages niet hard. NFR O-4
> (§4) schrijft daarom voor om dekking eerst *meetbaar* te maken vóór er een
> harde drempel op gezet wordt.

### 3.5 Documentatie

- **README.md:** aanwezig en bruikbaar (build, integratietests, wiki-links), maar
  deels verouderd (verwijst naar Java 8 en master-branch, externe voorbeeld-links
  zijn dood).
- **Javadoc:** wisselend. Veel methoden hebben de OpenMRS-conventie
  `<strong>Should</strong> …` als gedragsspecificatie, maar talrijke
  publieke methoden hebben lege of nietszeggende Javadoc
  (`/** @return */`, `/** @param properties */`) – zie `SettingsFormController`
  `getModel()`/`getProperties()`.
- **Inline-commentaar:** plaatselijk goed (uitleg bij de obs-conversie), elders
  afwezig bij juist de complexe methoden.
- **Architectuurdocumentatie:** ontbreekt in de repo; alleen verwijzingen naar de
  (externe) OpenMRS-wiki. Voor onderhoudbaarheid op lange termijn is een korte
  `ARCHITECTURE.md` (resource-framework, versiestrategie) wenselijk.

---

## 4. Voorgestelde non-functionele requirements (kwaliteitspoort in CI)

Deze NFR's zijn als CI-gate bedoeld. Drempels zijn **richtwaarden** die na een
eerste echte meting (SonarQube/JaCoCo/PMD) worden vastgezet. Aanpak: eerst meten,
dan **"geen verslechtering"** afdwingen, daarna stap voor stap aanscherpen.

| ID | NFR | Voorgestelde drempel | Handhaving |
| :--- | :--- | :--- | :--- |
| NFR-O-1 | Cyclomatische complexiteit per methode | ≤ 15 (build faalt bij nieuwe methoden > 15; bestaande uitschieters op uitzonderingslijst) | PMD/Checkstyle in CI |
| NFR-O-2 | Methodelengte | ≤ 60 regels (nieuw); bestaande > 100 op refactor-backlog | PMD |
| NFR-O-3 | Klassegrootte | ≤ 400 regels / ≤ 20 publieke methoden (nieuw) | PMD |
| NFR-O-4 | Regeldekking (na eerste meting) | Eerst meetbaar maken; daarna ≥ 70 % overall, ≥ 80 % op gewijzigde regels (patch-coverage gate) | JaCoCo `report` + `check` |
| NFR-O-5 | Codeduplicatie | ≤ 3 % gedupliceerde regels | SonarQube/CPD |
| NFR-O-6 | Statische-analysebevindingen | 0 nieuwe blocker/critical-issues | SonarQube quality gate |
| NFR-O-7 | Testframework | Eén framework (JUnit 5) voor nieuwe tests; migratiepad voor de 166 JUnit 4-klassen | Review + lint |
| NFR-O-8 | Taal-/buildniveau | Java-target expliciet en consistent met runtime; documenteer ondersteunde JDK | `maven-enforcer-plugin` |
| NFR-O-9 | Build reproduceerbaar & gate aanwezig | CI-pipeline bestaat, draait tests + analyse, faalt hard | GitHub Actions (zie §6 + security.md) |

---

## 5. Gap-tabel onderhoudbaarheid

Prioritering: **Hoog** = raakt direct testbaarheid/wijzigbaarheid van kerncode of
ontbrekende kwaliteitspoort; **Middel** = duidelijke schuld met beperkte blast
radius; **Laag** = cosmetisch/opruimwerk.

| ID | Onderwerp | Huidige situatie (IST) | Gewenste situatie (SOLL/NFR) | Gap | Prioriteit | Aanbevolen verbetering |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| O-1 | Ontbrekende kwaliteitspoort in CI | Geen werkende CI-pipeline in de repo; JaCoCo alleen `prepare-agent`, **geen `report`/`check`** → geen dekkings- of complexiteitsgate | NFR-O-9/O-4: pipeline die tests + analyse draait en hard faalt | Volledige gate ontbreekt | **Hoog** | GitHub Actions-workflow + JaCoCo `check` + PMD/Sonar (zie §6) |
| O-2 | God classes | `SwaggerSpecificationCreator` (1240 r), `RestUtil` (950 r), `BaseDelegatingResource` (901 r) | NFR-O-3: ≤ 400 r / ≤ 20 methoden | 2–3× over de norm | **Hoog** | Opsplitsen (Extract Class, zie §6.1) |
| O-3 | Zeer complexe methoden | `ObsResource1_8.setValue` cc≈40, `ConversionUtil.convert` cc≈40, `testOperationImplemented` cc≈37 | NFR-O-1: cc ≤ 15 | Factor 2,5–3 | **Hoog** | Extract Method + Strategy/polymorfisme (§6.1–6.2) |
| O-4 | Dekking niet meetbaar/geborgd | Geen JaCoCo-rapport; complexe kernmethoden vrijwel zeker ongedekt; nieuwe endpoints 100 % ongetest | NFR-O-4: meetbaar + ≥ 70/80 % | Meting + gate ontbreekt | **Hoog** | JaCoCo-rapport activeren; tests voor kernconversies en endpoints |
| O-5 | Duplicatie in SearchHandlers | 19 `…SearchHandler`-klassen met bijna-identieke `search()` | NFR-O-5: ≤ 3 % duplicatie | Substantieel | **Middel** | Template Method/Strategy: gemeenschappelijke basis-`SearchHandler` (§6.3) |
| O-6 | Inconsistente testframeworks | 166× JUnit 4 vs 6× JUnit 5 | NFR-O-7: één framework, migratiepad | Halve migratie | **Middel** | JUnit 5 als standaard; vintage-engine als brug; incrementeel migreren |
| O-7 | Slechte foutafhandeling | NPE als control-flow (`ChangePasswordController1_8:81`), lege catch-blokken (`SettingsFormController:151/160`) | Expliciete exceptions, geen stille catch | Anti-patroon | **Middel** | Specifieke exception (`ObjectNotFoundException`) + logging i.p.v. lege catch |
| O-8 | Java-/buildniveau vs runtime | `source/target=1.8`, README zegt Java 8, build draait op JDK 17 | NFR-O-8: expliciet, consistent, afgedwongen | Mismatch + verouderd niveau | **Middel** | `maven-enforcer` voor JDK-range; doeltaalniveau bewust kiezen/documenteren |
| O-9 | Dode/decoy-code & FIXME's | Ongebruikte `token`-param (`SessionController1_9:172`); vele `//FIXME` in Swagger-modellen | Geen dode code; FIXME's op backlog | Opruimwerk | **Laag** | Verwijderen/afronden; FIXME's omzetten naar tickets |
| O-10 | Magic values | Inline true/false-stringlijsten en speciale-geval-strings in `ObsResource1_8.setValue` | Benoemde constanten/enums | Leesbaarheid | **Laag** | Extract Constant / enum |
| O-11 | Documentatiehiaten | Lege Javadoc, geen `ARCHITECTURE.md`, verouderde README-links | Zinvolle Javadoc op publieke API + architectuurschets | Documentatieschuld | **Laag** | README actualiseren; korte `ARCHITECTURE.md`; Javadoc-lint |

---

## 6. Verbeteradvies hoge prioriteit – ontwerp-/refactoringpatronen

### 6.0 Quality gate herstellen (O-1, O-4) — fundament
Zonder gate verslechtert de rest opnieuw. Concreet:
1. Voeg JaCoCo `report`- en `check`-executions toe (de plugin staat al in
   `pom.xml:450` met alleen `prepare-agent`).
2. Voeg `maven-pmd-plugin`/Checkstyle toe met regels voor cc, methode- en
   klassegrootte (NFR-O-1..3).
3. Richt een CI-workflow in die `mvn verify` draait en faalt bij gate-overtreding
   (zie security.md §7 voor de pipeline-koppeling met NEN-controls A.8.25/A.8.29).
*Patroon:* niet code-refactoring maar **proces** – "fail fast"-kwaliteitspoort.

### 6.1 `ObsResource1_8.setValue` (`omod/.../openmrs1_8/ObsResource1_8.java:406`)
- **Probleem:** cc≈40, 118 regels; vertakt op datatype (complex, coded, location,
  numeric, boolean) in één methode.
- **Patronen:**
  - **Extract Method** – elk speciaal geval (`setComplexValue`, `setCodedValue`,
    `setLocationValue`, `setNumericValue`, `setBooleanValue`) in eigen methode.
  - **Replace Conditional with Polymorphism / Strategy** – introduceer
    `ObsValueSetter`-strategieën per datatype, geselecteerd via een map
    `datatype → strategy`. Halveert cc en maakt elk pad afzonderlijk testbaar.
  - **Extract Constant** – verplaats de true/false-stringlijsten (`:500-501`) naar
    constanten (raakt O-10).

### 6.2 `ConversionUtil.convert` (`omod-common/.../ConversionUtil.java:176`)
- **Probleem:** cc≈40, 118 regels; centrale type-conversie met lange
  `instanceof`/`if`-cascade.
- **Patronen:**
  - **Chain of Responsibility** of **register van `Converter<T>`-objecten**
    (vergelijk Spring `ConversionService`) – elk converter-type apart, uitbreidbaar
    zonder de god-methode aan te raken (**OCP**).
  - **Extract Method** voor de deelgevallen als tussenstap.

### 6.3 `SearchHandler`-duplicatie (O-5, 19 klassen in `omod/.../resource/**`)
- **Patronen:**
  - **Template Method** in een basisklasse `BaseSearchHandler` die het stramien
    (parameters lezen → valideren → pagineren → resultaat verpakken) vastlegt en
    alleen het service-specifieke deel als hook overlaat.
  - **Extract Method** voor herhaalde parameter-extractie en paginering naar
    gedeelde helpers.

### 6.4 God classes opsplitsen (O-2)
- `SwaggerSpecificationCreator` → **Extract Class** in bv. `SwaggerPathBuilder`,
  `SwaggerModelBuilder`, `OperationProber` (de huidige `testOperationImplemented`,
  `:246`). **Facade** houdt de publieke API stabiel.
- `RestUtil` → opsplitsen naar samenhangende helpers (`IpAddressMatcher`,
  `ErrorResponseFactory`, `ClasspathScanner`). Verhoogt cohesie (**SRP**).

### 6.5 Testbaarheid via dependency injection (DIP)
- Vervang directe `Context.getXxxService()`-aanroepen in nieuw/aangeraakt
  resource-codepad geleidelijk door geïnjecteerde services, zodat unit-tests
  zonder volledige OpenMRS-context kunnen draaien. Ondersteunt NFR-O-4.

---

## 7. Conclusie Deel 1

De module heeft een doordachte, schaalbare architectuur, maar draagt zichtbare
**technische schuld**: enkele god classes en zeer complexe methoden, forse
duplicatie in de search-laag, een halfvoltooide testframework-migratie en — het
meest urgent — **het ontbreken van een werkende kwaliteitspoort** (geen CI-gate,
JaCoCo niet rapporterend). De hoogste prioriteit is daarom procesmatig: eerst de
gate (O-1/O-4) herstellen om verdere erosie te stoppen, daarna de drie cc≈40-
brandhaarden (O-3) en god classes (O-2) gericht refactoren met **Extract
Method/Class**, **Strategy** en **Template Method**. Pas met meetbare dekking en
analyse in CI worden de NFR's uit §4 handhaafbaar.
