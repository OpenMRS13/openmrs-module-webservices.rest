# 2. Aangepast Ontwerp en Ontwerponderbouwing

Dit document beschrijft het aangepaste ontwerp voor de geselecteerde verbeteringen uit de backlog (**PM-1**, **PM-2** en **PM-3**). Het ontwerp is erop gericht om de onderhoudbaarheid (aanpasbaarheid en testbaarheid) en de beveiliging van de module structureel te verhogen.

---

## 1. Ontwerpprincipes (SOLID, DRY)

Bij het herontwerp zijn de volgende ontwerpprincipes leidend:

1.  **Single Responsibility Principle (SRP):**
    *   *Toepassing:* Controllers mogen alleen verantwoordelijk zijn voor het routeren en delegeren van HTTP-requests naar de service-laag. De logica voor audit-logging (**PM-2**) en de complexe serialisatie van objecten (**PM-1**) worden verplaatst naar aparte, gespecialiseerde componenten.
2.  **Separation of Concerns (SoC):**
    *   *Toepassing:* Presentatie/data-formaten (JSON-generatie) worden gescheiden van business logica. We elimineren ad-hoc string-constructie en delegeren dit aan Spring's content-negotiation / Jackson-framework.
3.  **Don't Repeat Yourself (DRY):**
    *   *Toepassing:* In plaats van in elke controller handmatig audit-logs weg te schrijven of handmatig invoer te sanitiseren, centraliseren we deze logica.

---

## 2. Refactoring Ontwerpen

### PM-1: Refactoring van JSON-generatie (`SettingsFormController`)

#### Oorspronkelijk Ontwerp (Lage Onderhoudbaarheid):
De `searchProperties` methode bouwt handmatig een JSON-string op met string-concatenatie:
```java
StringBuilder result = new StringBuilder("[");
for (GlobalProperty gp : Context.getAdministrationService().getGlobalPropertiesByPrefix(prefix)) {
    result.append("{\"property\":\"").append(gp.getProperty())
          .append("\",\"value\":\"").append(gp.getPropertyValue()).append("\"},");
}
```

#### Nieuw Ontwerp:
We maken gebruik van OpenMRS's ingebouwde klasse `SimpleObject` (een gespecialiseerde `Map` die automatisch door Spring's `MappingJackson2HttpMessageConverter` wordt geserialiseerd naar valide JSON).
```java
List<SimpleObject> propertiesList = new ArrayList<>();
for (GlobalProperty gp : properties) {
    propertiesList.add(SimpleObject.create("property", gp.getProperty(), "value", gp.getPropertyValue()));
}
return propertiesList; // Spring serialiseert dit automatisch naar een JSON-array!
```
*   **Toegepast Refactoringpatroon:** *Substitute Algorithm* en *Introduce Formatter*.
*   **Resultaat:** Geen risico op JSON-syntaxfouten, automatische escaping van quotes, en directe uitbreidbaarheid.

---

### PM-2: Introductie van `RestAuditLog` Helper (Logging-architectuur)

Om te voldoen aan **NEN 7510 Control A.8.15** (Logregistratie) moeten kritieke acties (zoals inloggen en PHI-inzage) worden gelogd. In plaats van ad-hoc logging in controllers, ontwerpen we een herbruikbare `RestAuditLog` component.

#### Ontwerp van de `RestAuditLog` Klasse:
```java
package org.openmrs.module.webservices.rest.web;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openmrs.api.context.Context;

public class RestAuditLog {
    private static final Log log = LogFactory.getLog(RestAuditLog.class);

    public static void logEvent(String resource, String action, String details) {
        String username = Context.isAuthenticated() ? Context.getAuthenticatedUser().getUsername() : "ANONYMOUS";
        String ipAddress = "UNKNOWN"; // Kan eventueel uit RequestContext worden gehaald
        
        // Formateer het logboek op een gestructureerde manier (bijv. voor log-aggregators zoals Splunk of ELK)
        String logMessage = String.format(
            "REST_AUDIT | User: %s | Action: %s | Resource: %s | Details: %s",
            username, action, resource, details
        );
        log.info(logMessage);
    }
}
```
*   **Toegepaste Ontwerppatronen:** *Helper Pattern* en *Facade Pattern* voor logging.
*   **Resultaat:** Centraal beheerd log-formaat. Als we in de toekomst logs naar een database of specifieke syslog-server willen sturen, hoeft dit maar op één plek te worden aangepast.

---

### PM-3: Escaping en Sanitatie in `SwaggerDocController`

#### Oorspronkelijk Ontwerp:
```java
public String debug(@RequestParam("tag") String tag) {
    return "<h1>Debugging Tag: " + tag + "</h1>";
}
```

#### Nieuw Ontwerp:
We sanitiseren de input met Spring's `HtmlUtils.htmlEscape(tag)` en dwingen een expliciete `Content-Type` header af om te voorkomen dat de browser de string als actieve HTML/JavaScript interpreteert:
```java
import org.springframework.web.util.HtmlUtils;

@RequestMapping(value = "/debug", method = RequestMethod.GET, produces = "text/plain")
@ResponseBody
public String debug(@RequestParam("tag") String tag) {
    return "Debugging Tag: " + HtmlUtils.htmlEscape(tag);
}
```
*   **Resultaat:** XSS is onmogelijk doordat de invoer HTML-escaped is en de respons als platte tekst (`text/plain`) wordt geserveerd.

---

## 3. Evaluatie van Alternatieven

### Alternatief A: Spring AOP (Aspect-Oriented Programming) voor Audit-logging
*   **Beschrijving:** Gebruik maken van Spring `@Aspect` om automatisch alle controller-methoden te intercepten en te loggen.
*   **Waarom afgewezen:** Hoewel AOP zeer elegant is en code-duplicatie minimaliseert, introduceert het runtime-overhead en vereist het complexe AspectJ-configuratie. Binnen de OpenMRS 2.x runtime-omgeving (met OSGi-achtige module-loaders) leidt AOP-classloading vaak tot runtime-conflicten. Een expliciete, statische helper-klasse (`RestAuditLog`) is robuuster en makkelijker te debuggen.

### Alternatief B: Handmatige JSON-escaping via String-vervanging
*   **Beschrijving:** Zelf quotes en backslashes escapen met `replace("\"", "\\\"")` in de String-concatenatie.
*   **Waarom afgewezen:** Dit is extreem foutgevoelig en lost het onderliggende probleem (slechte onderhoudbaarheid door verweven concerns) niet op. Het delegeren aan Jackson (`SimpleObject`) is de industriestandaard voor Java/Spring applicaties.
