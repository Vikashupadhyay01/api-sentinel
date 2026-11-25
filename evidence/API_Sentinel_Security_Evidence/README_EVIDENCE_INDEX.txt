API-SENTINEL — SECURITY TESTING EVIDENCE INDEX
Role: Member 1 — Security Testing
Date of screenshots: 25 November 2026

The filenames describe the visible screenshot content. Initial troubleshooting screenshots are retained for chronology; they are not all successful test results.

01_Git_Branch_Status_Check.png
  PowerShell check of the current Git branch.
02_Repository_Root_Files_Inspection.png
  Inspection of the API-Sentinel repository root and top-level folders.
03_Repository_Folder_Structure_Inspection.png
  Further inspection of repository folders and files.
04_Git_Merge_Commit_Message.png
  Git merge message editor while integrating origin/main into the security branch.
05_Repository_Changes_and_New_Files.png
  PowerShell view of repository changes and newly added files.
06_Reports_Folder_and_Dashboard_Files.png
  Inspection of the reports folder and dashboard frontend files.
07_Dashboard_Vite_Development_Server_Started.png
  Vite frontend development server started and showing local dashboard URL.
08_Dashboard_Initial_Backend_Offline_State.png
  Dashboard initially reports that the detection backend is offline.
09_Detection_API_OpenAPI_Endpoint_Check.png
  PowerShell request/check for the detection API OpenAPI endpoint.
10_Detection_API_Runtime_Exception_Log.png
  Detection API runtime exception during initial startup/testing.
11_Flask_ASGI_Compatibility_Error.png
  Traceback showing Flask application called through an incompatible ASGI setup.
12_Detection_API_Port_and_Python_Environment_Troubleshooting.png
  Troubleshooting port 9000, PowerShell execution policy, and Python command availability.
13_Detection_API_Server_Started_Successfully.png
  Detection API starts and reports its local listening address and event log.
14_API_Sentinel_Dashboard_Home_Overview.png
  Dashboard home overview showing OWASP alert categories and endpoint coverage.
15_Security_Alerts_Dashboard_BOLA_and_Shadow_Findings.png
  Security alerts table showing three BOLA alerts and one Shadow API alert.
16_BOLA_Finding_Order_301_Alert_Overview.png
  BOLA finding details for Alice accessing order ID 301.
17_BOLA_Finding_Order_301_Exposed_Response_Evidence.png
  BOLA finding details showing successful HTTP 200 response and exposed order data for order 301.
18_BOLA_Finding_Order_202_Alert_Overview.png
  BOLA finding details for Alice accessing order ID 202.
19_BOLA_Finding_Order_202_Exposed_Response_Evidence.png
  BOLA finding details showing successful HTTP 200 response and exposed order data for order 202.
20_BOLA_Finding_Order_201_Alert_Overview.png
  BOLA finding details for Alice accessing order ID 201.
21_BOLA_Finding_Order_201_Exposed_Response_Evidence.png
  BOLA finding details showing successful HTTP 200 response and exposed order data for order 201.
22_Normal_Traffic_Proxy_Connection_Refused_Error.png
  Normal traffic script failed because the capture proxy on port 8080 was not listening.
23_Normal_Traffic_Connection_Error_Traceback.png
  Continuation of the normal traffic connection-refused traceback.
24_API_Sentinel_Capture_Proxy_Started.png
  Capture proxy listening on 127.0.0.1:8080 and forwarding to mock API port 8000.
25_Normal_Traffic_Baseline_Success.png
  Benign traffic simulation succeeds for Alice, Bob, and Carol, reading only their own orders.
26_Scripted_BOLA_Attack_Execution_Results.png
  BOLA attack simulation: Alice successfully reads other users’ order IDs 201, 202, and 301 in the vulnerable lab.
27_Dashboard_BOLA_and_Shadow_Security_Alerts.png
  Dashboard alert list showing the detected BOLA and Shadow API findings.
28_Shadow_API_Admin_Export_Endpoint_Details.png
  Endpoint details classify GET /api/v1/admin/export as an undocumented Shadow API under OWASP API9.
29_API_Endpoint_Inventory_Classification.png
  Endpoint inventory listing observed documented and undocumented API endpoints.
30_ID_Enumeration_Attack_Simulation_Output.png
  Enumeration script scans order IDs 100 through 125 and identifies valid records.
31_Dashboard_Enumeration_Security_Alert.png
  Security alerts dashboard showing the high-severity enumeration finding.
32_Enumeration_Finding_Order_ID_109_Alert_Overview.png
  Enumeration finding details for Alice requesting order ID 109.
33_Enumeration_Finding_Request_Response_and_Remediation.png
  Enumeration finding details showing request/response and remediation guidance.
34_Shadow_and_Zombie_API_Testing_Execution.png
  Shadow and Zombie API script reports five records from the shadow export and three accounts from the legacy API.
35_Dashboard_Security_Alerts_After_Shadow_Zombie_Testing.png
  Security alerts dashboard after the Shadow and Zombie API test run.
36_Zombie_API_Finding_Response_and_Exposed_Accounts.png
  Zombie API finding showing GET /api/v0/users returned three user records.
37_Zombie_API_Finding_Overview_and_Threat_Explanation.png
  Zombie API finding overview for the deprecated /api/v0/users endpoint.
38_Enumeration_Attack_Rerun_Terminal_Evidence.png
  Terminal evidence of the enumeration attack script run.
39_Backend_Pytest_Automated_Test_Suite_Execution.png
  Beginning of backend pytest run; 182 tests collected and passing.
40_Backend_Pytest_Discovery_and_Parser_Tests.png
  Backend automated test progress showing discovery and parser tests passing.
41_Backend_Pytest_Phase_and_Export_Tests.png
  Backend automated test progress showing phase, reporting, export, and related tests passing.
42_Backend_Pytest_PII_RateLimit_and_Enumeration_Tests.png
  Backend automated test progress showing PII masking, rate-limit, and enumeration tests passing.
43_Final_API_Endpoint_Inventory_Zombie_and_Shadow_Classification.png
  Endpoint inventory showing /api/v0/users as Zombie and /api/v1/admin/export as Shadow, with documented endpoints listed.