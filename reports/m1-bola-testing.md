# Member 1 – Security Testing Report

**Project:** API-Sentinel – Runtime BOLA & Shadow API Detection Engine  
**Role:** Member 1 – Security Testing  
**Branch:** `m1-security`  
**Date:** 12 November 2026

## 1. Testing Environment

- Operating System: Windows
- Backend: Python
- Mock API: `127.0.0.1:8000`
- Detection API: `127.0.0.1:9000`
- Capture Proxy: `127.0.0.1:8080`

## 2. Normal Traffic Testing

Executed:

`python attack-sim/normal_traffic.py http://127.0.0.1:8080`

**Observed results:**
- Alice logged in successfully.
- Alice accessed orders 101 and 102.
- Bob logged in successfully.
- Bob accessed orders 201 and 202.
- Carol logged in successfully.
- Carol accessed order 301.
- All displayed requests returned HTTP 200.

## 3. BOLA Attack Testing

Executed:

`python attack-sim/bola_attack.py http://127.0.0.1:8080`

**Observed results:**
- Alice successfully accessed her own order 101.
- Alice also accessed Bob's orders 201 and 202.
- Alice also accessed Carol's order 301.
- All three unauthorized order requests returned HTTP 200.
- The undocumented admin export endpoint returned HTTP 200.

## 4. Initial Findings

The mock API allowed Alice to access other users' order records without authorization.

This demonstrates the intended BOLA vulnerability in the test environment.

The admin export endpoint was also accessible during testing.

## 5. Pending Verification

- Verify whether the detection engine generates BOLA alerts.
- Verify whether `/api/stats` returns valid detection statistics.
- Capture detection logs and dashboard evidence.
- Retest after remediation.

## 6. Conclusion

Normal traffic simulation and scripted BOLA attack simulation were executed successfully against the local mock API through the capture proxy.

The observed unauthorized HTTP 200 responses demonstrate the BOLA test case. Detection results still require verification.