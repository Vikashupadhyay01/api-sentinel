# API-Sentinel – Final Security Testing Report
**Member 1: Security Testing | Axlero Solutions – Group 1**

**Project:** API-Sentinel – Runtime BOLA & Shadow API Detection Engine
**Prepared by:** Member 1 – Security Testing
**Report date:** 25 November 2026

## 1. Executive Summary
Security testing was performed against the deliberately vulnerable API-Sentinel local lab. The work covered benign baseline traffic, scripted Broken Object Level Authorization (BOLA) testing, undocumented Shadow API access, legacy Zombie API access, rapid order-ID enumeration, dashboard verification, and the backend automated test suite.

The observed attack simulations demonstrated that the mock API returned successful responses for cross-user order access, an undocumented administrative export endpoint, and a deprecated user endpoint. The monitoring dashboard generated corresponding security findings. The backend automated test suite completed with 182 passing tests in 2.53 seconds.

This report records the observed results from the supplied terminal and dashboard screenshots. It does not claim that the vulnerabilities have been fixed or that remediation has been retested.

## 2. Role and Scope
Assigned role: Member 1 – Security Testing.

Primary assigned activity: scripted BOLA attack testing. Supporting validation included normal traffic, enumeration, and Shadow/Zombie API scenarios so that the monitoring pipeline and dashboard could be checked end to end.

Scope was restricted to the local API-Sentinel demonstration environment running on the user's own machine. The target URLs shown in the evidence use loopback addresses (127.0.0.1 / localhost). No external or third-party systems were tested.

## 3. Test Environment
Operating environment visible in the terminal evidence: Windows PowerShell 5.1.

Project directory: D:\Axlero\api-sentinel.

Python executable: project virtual environment at .venv\Scripts\python.exe.

Python version reported by pytest: 3.14.10.

Pytest version reported by pytest: 9.2.0.

Mock API: http://127.0.0.1:8000.

Capture proxy: http://127.0.0.1:8080.

Dashboard: http://localhost:5173.

Proxy event log shown at startup: data\events.jsonl.

Dashboard operating mode visible in screenshots: PASSIVE.

## 4. Test Setup and Execution
The mock API was started using the project's virtual-environment Python executable and mock-api\flask_app.py. The terminal confirmed that the deliberately vulnerable lab API was listening on 127.0.0.1:8000.

The capture proxy was started using capture\proxy.py. Its startup output confirmed that it listened on 127.0.0.1:8080 and forwarded upstream to 127.0.0.1:8000.

An initial normal-traffic attempt failed with a connection-refused error because the proxy endpoint on port 8080 was not accepting connections at that time. After the proxy was started, the normal-traffic script was rerun with http://127.0.0.1:8080 as its target and completed successfully.

Attack simulation scripts were directed to the proxy URL so that their requests could be observed by API-Sentinel.

## 5. Test Cases and Results
TC-01 – Normal traffic baseline: The normal_traffic.py script completed for Alice, Bob, and Carol. Each user logged in, accessed their own profile, listed owned orders, and read their own order records. The output showed successful HTTP 200 responses for the owned resources. This is the benign baseline evidence.

TC-02 – BOLA cross-user object access: The bola_attack.py script authenticated as Alice, successfully read Alice's own order 101, and then requested orders 201, 202, and 301 belonging to other users. The terminal showed HTTP 200 responses and returned order data, including owner identifiers. The dashboard displayed three HIGH BOLA findings for object IDs 201, 202, and 301 on /api/v1/orders/{id}, mapped to OWASP API1.

TC-03 – Shadow API access: The test called GET /api/v1/admin/export. The terminal showed HTTP 200 and reported that five order records were returned from the undocumented export endpoint. The dashboard classified /api/v1/admin/export as a Shadow endpoint and displayed a MEDIUM finding mapped to OWASP API9. The endpoint details drawer stated that the endpoint was not documented in the OpenAPI specification.

TC-04 – ID enumeration: The enumeration_attack.py script requested order IDs 100 through 125, completing 26 requests. The output showed two valid records (IDs 101 and 102) and 404 responses for the other requested IDs. The dashboard generated a HIGH ENUMERATION finding for /api/v1/orders/{id}, with the alert explanation indicating ten distinct object IDs accessed within ten seconds. The dashboard mapped the finding to OWASP API6.

TC-05 – Zombie API access: The test called GET /api/v0/users. The terminal showed HTTP 200 and reported that three user accounts were returned from the legacy v0 endpoint. The dashboard classified /api/v0/users as a Zombie endpoint and displayed a HIGH finding mapped to OWASP API9.

TC-06 – Automated backend tests: The command .\.venv\Scripts\python.exe -m pytest backend\tests\ -v completed with 182 passed in 2.53 seconds. The visible test output included API, BOLA, discovery, parser, phase, PII masking, rate-limit, and enumeration-related test groups.

## 6. Observed Dashboard Results
After the BOLA and Shadow API scenarios, the dashboard showed four alerts: three BOLA alerts and one Shadow alert.

After the enumeration scenario, the dashboard showed five alerts, including the Enumeration finding.

After the Shadow and Zombie API test run, the dashboard showed six alerts, including the Zombie finding.

The endpoint inventory screenshot showed documented endpoints and the discovered Shadow and Zombie endpoints. The visible classifications included GET /api/v1/admin/export as shadow and GET /api/v0/users as zombie.

## 7. Findings Summary
Finding 1 – BOLA: Alice could retrieve order objects owned by other users by changing the order ID. The mock API returned HTTP 200 for IDs 201, 202, and 301. This demonstrates missing or ineffective object-level authorization in the lab endpoint.

Finding 2 – Shadow API: The undocumented GET /api/v1/admin/export endpoint was reachable and returned five order records. This indicates an API inventory/documentation gap and an exposed administrative function in the lab.

Finding 3 – Enumeration: Rapid sequential order-ID requests revealed valid object IDs. The detector generated an enumeration alert. The script found two valid records in the scanned range; the dashboard's alert explanation reported ten distinct IDs within ten seconds.

Finding 4 – Zombie API: The legacy GET /api/v0/users endpoint remained accessible and returned three user account records. This indicates an obsolete API version still exposed in the lab.

Finding 5 – Benign baseline: Normal user activity against each user's own records completed successfully. This provides a comparison case for the attack simulations.

## 8. Recommendations
For BOLA: enforce server-side ownership/authorization checks for every object access, using the authenticated principal and the requested object's owner relationship. Do not rely on unpredictable IDs as an authorization control.

For Shadow APIs: maintain an authoritative API inventory, compare observed routes against the OpenAPI contract, restrict administrative endpoints, and remove or explicitly document approved routes.

For enumeration: apply per-identity and per-endpoint rate limits, detect unusual sequential access patterns, and consider response controls that avoid exposing whether arbitrary object identifiers exist. Ensure legitimate users are not blocked by overly broad thresholds.

For Zombie APIs: decommission obsolete API versions, remove unused route handlers, and monitor for traffic to retired routes.

For validation: rerun the same tests after fixes and confirm that unauthorized object requests are denied, undocumented/retired endpoints are unavailable or properly protected, and detection remains effective.

## 9. Limitations and Validation Notes
The mock API is explicitly labelled deliberately vulnerable and for lab use only. Results should not be interpreted as evidence about a production service.

The report is based on the screenshots and terminal outputs supplied for this work. It does not independently inspect the live source tree or event log.

The 182 passing pytest tests show that the repository's automated tests passed in the recorded run; they do not prove that the simulated vulnerabilities are remediated. In fact, the attack scripts intentionally demonstrated successful access in the vulnerable mock API.

The initial connection-refused error was resolved by starting the capture proxy before rerunning the baseline test.

No remediation changes or post-remediation retest results were supplied. Remediation is therefore recommended, not marked completed.

## 10. Evidence Register
Evidence screenshots should be stored under reports/evidence/. The prepared evidence ZIP contains descriptively named PNG files and a README_EVIDENCE_INDEX.txt file. Keep the original screenshots and avoid editing their technical content.

Recommended evidence groups: (a) service startup and proxy setup; (b) normal traffic baseline; (c) BOLA attack terminal output and dashboard findings; (d) Shadow endpoint details and endpoint inventory; (e) enumeration terminal output and alert details; (f) Zombie API terminal output and alert details; (g) automated pytest output; (h) final endpoint inventory.

Evidence filenames should describe the actual content, for example: Normal_Traffic_Baseline_Success, Scripted_BOLA_Attack_Execution_Results, Dashboard_BOLA_and_Shadow_Security_Alerts, ID_Enumeration_Attack_Simulation_Output, Zombie_API_Finding_Overview, and Backend_Pytest_Automated_Test_Suite_Execution.

## 11. Conclusion
The assigned security-testing activities were executed against the local API-Sentinel lab. The evidence demonstrates successful benign baseline traffic, reproduction and detection of BOLA, Shadow API, enumeration, and Zombie API scenarios, and a successful automated backend test run with 182 passing tests.

The testing execution is complete based on the supplied evidence. The overall assignment should be considered ready for submission only after the report and evidence are added to the assigned Git branch, pushed to the team repository, and reviewed/accepted by the team lead.
