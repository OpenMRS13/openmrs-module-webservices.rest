# Systeem analyse van OpenMRS REST Web Services Module

# 1. Context
### 1.1 Project Beschrijving
Het gekozen project is `openmrs-module-webservices.rest` dit is een module van OpenMRS. OpenMRS is een open-source patiëntendossier systeem dat wereldwijd wordt ingezet, voornamelijk door landen met beperkte middelen. De module stelt de volledige OpenMRS API beschikbaar als REST-Webservices, waardoor externe applicaties patiëntgegevens kunnen opvragen en registreren.

### 1.2 Gevoelige gegevens die worden verwerkt (kroonjuwelen)
Via de REST-endpoints van deze module worden de de volgende categorieën **bijzondere persoongegevens** en medische informatie neergezet:

| # | Gegevenscategorie | REST-resource (voorbeeld) | Classificatie |
| :--- | :--- | :--- | :--- |
| **1** | **Patiëntidentificatie**: naam, geboortedatum, geslacht, patiënt-ID | `/ws/rest/v1/patient` | Bijzondere persoonsgegevens (AVG art. 9) |
| **2** | **Medische observaties**: laberatoriumwaarde, vitale functies, klachten | `/ws/rest/v1/obs` | Medisch beroepsgeheim |
| **3** | **Diagnose & aandoeningen**: gecodeerde diagnoses, problemenlijst | `/ws/rest/v1/condition` | Bijzondere persoonsgegevens (AVG art. 9) | 