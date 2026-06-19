# Handmatige SAST-sweep (geen geautomatiseerde SAST-tool beschikbaar)

**Methode:** HANDMATIG GEVERIFIEERD via `git grep` patronen over `*.java` (vendored swagger-ui uitgesloten).
Geen CodeQL/semgrep/snyk-code/bandit/gosec beschikbaar (zie `tool-inventory.txt`).
**Commit:** 19d1b21a09019d2defbdcc20ca2ef961f3ad117f  ·  **Datum:** 2026-06-19
**Scope:** 676 `.java`-bestanden (`git ls-files '*.java' | wc -l`).

> Doel: vaststellen of klassieke kwetsbaarheidsklassen aantoonbaar in de MODULE-broncode voorkomen.
> 'GEEN MATCHES' = patroon niet aangetroffen (afwezigheid van dat patroon), geen garantie op volledige afwezigheid van risico.

### 1. Zwakke/eigen cryptografie (MD5/SHA1/DES/ECB/Cipher/Random)
```
patroon: MD5|SHA-?1|"DES"|AES/ECB|ECB/|Cipher\.getInstance|MessageDigest\.getInstance|SecretKeySpec|new Random\(|Math\.random
RESULTAAT: GEEN MATCHES
```

### 2. SQL/HQL/command-injectie (raw query/exec)
```
patroon: createSQLQuery|createNativeQuery|Runtime\.getRuntime|ProcessBuilder|\.exec\(
RESULTAAT: GEEN MATCHES
```

### 3. Native Java-deserialisatie
```
patroon: ObjectInputStream|readObject\(|readUnshared
RESULTAAT: GEEN MATCHES
```

### 4. XML-parsing / XXE (eigen parsers)
```
patroon: DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|SAXReader|SAXBuilder|XMLReader
RESULTAAT: GEEN MATCHES
```

### 5. TLS-/certificaatvalidatie uitschakelen
```
patroon: TrustManager|HostnameVerifier|setHostnameVerifier|ALLOW_ALL|checkServerTrusted
RESULTAAT: GEEN MATCHES
```

### 6. Netwerk-calls / SSRF-vectoren
```
patroon: openConnection|HttpURLConnection|new URL\(|RestTemplate
omod/src/main/java/org/openmrs/module/webservices/rest/web/v1_0/resource/openmrs1_8/ModuleActionResource1_8.java:159:			URL downloadUrl = new URL(installUri);
... (totaal 1 matchregels)
```

### 7. Debug-/info-lekkage (printStackTrace/System.out) in MAIN-code
```
patroon: printStackTrace|System\.out\.print|System\.err\.print
integration-tests/src/test/java/org/openmrs/module/webservices/rest/ITBase.java:70:				System.out.println("Waiting for server at " + startupUri + " for " + timeout / 1000 + " more seconds...");
integration-tests/src/test/java/org/openmrs/module/webservices/rest/ITBase.java:98:						System.out.println(e.toString());
integration-tests/src/test/java/org/openmrs/module/webservices/rest/ITBase.java:102:						System.out.println("Waiting for "
omod-common/src/test/java/org/openmrs/module/webservices/rest/test/OpenmrsProfileRule.java:81:			System.out.println("Ignored " + description.getMethodName() + " (run only on OpenMRS "
omod-common/src/test/java/org/openmrs/module/webservices/rest/test/Util.java:38:		System.out.println(toPrint);
omod/src/test/java/org/openmrs/module/webservices/rest/doc/SwaggerSpecificationCreatorTest.java:151:				System.err.println("The " + key + " table has a different number of rows (" + beforeCounts.get(k
omod/src/test/java/org/openmrs/module/webservices/rest/web/v1_0/controller/RestControllerTestUtils.java:229:		System.out.println(stringWriter.toString());
omod/src/test/java/org/openmrs/module/webservices/rest/web/v1_0/controller/jupiter/RestControllerTestUtils.java:213:		System.out.println(stringWriter.toString());
omod/src/test/java/org/openmrs/module/webservices/rest/web/v1_0/controller/openmrs1_9/ClobDatatypeStorageControllerTest.java:121:			e.printStackTrace();
omod/src/test/java/org/openmrs/module/webservices/rest/web/v1_0/controller/openmrs1_9/EncounterController1_9Test.java:200:		System.out.println("");
omod/src/test/java/org/openmrs/module/webservices/rest/web/v1_0/resource/openmrs1_9/LocationAttributeResource1_9Test.java:56:			ex.printStackTrace();
omod/src/test/java/org/openmrs/module/webservices/rest/web/v1_0/resource/openmrs1_9/ProviderAttributeResource1_9Test.java:56:			ex.printStackTrace();
omod/src/test/java/org/openmrs/module/webservices/rest/web/v1_0/resource/openmrs2_0/ConceptAttributeResource2_0Test.java:56:			ex.printStackTrace();
... (totaal 13 matchregels)
```

### 8. CORS / X-Forwarded-For / IP
```
patroon: CrossOrigin|Access-Control-Allow|X-Forwarded-For|getRemoteAddr
omod-common/src/main/java/org/openmrs/module/webservices/rest/web/filter/AuthorizationFilter.java:70:		if (!RestUtil.isIpAllowed(request.getRemoteAddr())) {
omod-common/src/main/java/org/openmrs/module/webservices/rest/web/filter/AuthorizationFilter.java:72:			RestAuditLog.accessDenied("ip-not-allowed", request.getRemoteAddr());
omod-common/src/main/java/org/openmrs/module/webservices/rest/web/filter/AuthorizationFilter.java:75:			    "IP address '" + request.getRemoteAddr() + "' is not authorized");
omod-common/src/main/java/org/openmrs/module/webservices/rest/web/filter/AuthorizationFilter.java:97:								RestAuditLog.authFailure(null, request.getRemoteAddr());
omod-common/src/main/java/org/openmrs/module/webservices/rest/web/filter/AuthorizationFilter.java:105:								RestAuditLog.authFailure(null, request.getRemoteAddr());
omod-common/src/main/java/org/openmrs/module/webservices/rest/web/filter/AuthorizationFilter.java:115:							RestAuditLog.authSuccess(attemptedUsername, request.getRemoteAddr());
omod-common/src/main/java/org/openmrs/module/webservices/rest/web/filter/AuthorizationFilter.java:121:							RestAuditLog.authFailure(attemptedUsername, request.getRemoteAddr());
... (totaal 7 matchregels)
```

## Samenvatting handmatige SAST
- Geen eigen crypto, geen raw SQL/command-injectie, geen native deserialisatie, geen eigen XXE-parsers,
  geen uitgeschakelde TLS-validatie in de MODULE-broncode (patronen 1-5: geen relevante main-code matches).
- Netwerk: `new URL(installUri)` in ModuleActionResource1_8 (admin-gated module-install) — zie bevinding SSRF.
- printStackTrace/System.out uitsluitend in TEST-code.
- IP-check via getRemoteAddr in AuthorizationFilter (geen X-Forwarded-For-parsing in de module).
