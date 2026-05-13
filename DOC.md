#  Security Scanning Architecture (DAST & SAST)

This document explains the **security testing architecture** implemented in the CI/CD pipeline, covering both **DAST (Dynamic Application Security Testing)** and **SAST (Static Application Security Testing)**.

---

#  DAST – Dynamic Application Security Testing


##  Architecture Overview

The DAST architecture is based on authenticated scanning using Azure AD and OWASP ZAP.

###  Flow Description

1. **Azure Entra ID (Client Secrets)**

   * Stored securely in CI/CD Variable Groups

2. **Token Generation (Runtime)**

   * A Bash script uses client credentials
   * Generates a **Bearer Access Token**

3. **Authenticated Scan (OWASP ZAP)**

   * Token is injected into scan headers
   * Ensures access to protected endpoints

4. **Security Testing Execution**

   * OWASP ZAP scans the running backend
   * Detects vulnerabilities in real conditions

---

##  Architecture Diagram

<img src="./images/ARCHDAST.png" width="450" />

---

##  Endpoint Discovery Strategy

###  Challenge

* Docker version of OWASP ZAP does not always discover all API endpoints.

###  Solutions

#### 1. Swagger-based Discovery

* If available, `/swagger.json` is used
* Automatically imports API endpoints into ZAP

#### 2. Automation Framework

* ZAP automation framework uses Swagger definitions

#### 3. Manual Endpoint Definition (Fallback)

If Swagger is not available:

* `/api/dashboard`
* `/api/health`
* Other critical endpoints are manually defined

---

## 📌 DAST Benefits

* Fully authenticated scanning
* Real-world attack simulation
* CI/CD integrated security validation
* Improved API endpoints discovery via Swagger

---

#  SAST – Static Application Security Testing



##  Architecture Overview

The SAST pipeline is built using two main open-source tools:

###  1. Opengrep
<img src="./images/opengrep.png" width="150" />


* Detects security vulnerabilities in source code
* Identifies insecure patterns and risky code usage

###  2. Gitleaks
<img src="./images/gitleaks.png" width="60" />

* Detects secrets in the repository
* Examples:

  * API keys
  * Tokens
  * Passwords

---


logos de OpenGrep et GitLeaks

---

## Intégration dans le pipeline CI/CD

1. Le code source est récupéré automatiquement dans le pipeline CI/CD.

2. Les outils SAST sont ensuite exécutés :

   * **Opengrep** → détection des vulnérabilités et mauvaises pratiques de sécurité
   * **Gitleaks** → détection des secrets exposés (tokens, mots de passe, clés API, etc.)

3. Les résultats des scans sont générés au format **SARIF**, permettant une standardisation des rapports de sécurité.

4. Les rapports sont ensuite convertis au format **JSON** afin de :

   * faciliter leur traitement automatisé,
   * générer un rapport HTML consolidé,
   * et exploiter les résultats via l’extension **SARIF Viewer** dans Azure DevOps.

Le mécanisme de **Quality Gate** est implémenté à l’aide de scripts Bash exploitant les rapports JSON ainsi que l’historique Git afin de détecter uniquement les nouvelles vulnérabilités introduites dans les Pull Requests.

<img src="./images/Screenshot 2026-05-13 102735.png.png" width="700" />

<img src="./images/Screenshot 2026-05-12 230154.png" width="700" />

5. Enfin, les différents rapports générés sont publiés comme **artifacts du pipeline** afin de garantir leur traçabilité et leur consultation ultérieure.


Le dossier SAST/ contient les details

---



---
