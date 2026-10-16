# Splunk Log Investigation: SSH Brute Force

A hands-on SOC Analyst L1 project where I used Splunk to investigate failed login activity in Linux authentication logs and documented the findings.

## Objective
Find brute force activity, identify the top attacking IPs, check whether any attack succeeded, and write an investigation report.

## Dataset
Splunk's official tutorial sample data (`tutorialdata.zip`). It is sample data, so the activity is not a real incident. The dataset is not included in this repo.

## Tools Used
- Splunk Enterprise (SPL searches, statistics, timechart)
- AbuseIPDB (IP reputation)
- Git and GitHub

## What I Did
1. Installed Splunk Enterprise and loaded the sample data.
2. Searched failed password events and ranked attacking IPs.
3. Analyzed the usernames tried by the top IP.
4. Checked for successful logins from attacking IPs.
5. Built an hourly timeline of attempts.
6. Checked the top IP on AbuseIPDB.
7. Wrote an investigation report with findings and recommended actions.

## Key Findings
- Top IP made 948 failed attempts across 140 usernames (root, admin, operator and more).
- Attempts came in short daily bursts, which suggests automation.
- No successful login was found, so the attack did not succeed.
- A clean AbuseIPDB score (0%) does not prove an IP is harmless.

## Repository Structure
- `Reports/investigation-report.md`: full investigation report with all SPL searches
- `Evidence/`: screenshots of Splunk results

## What I Learned
- Writing SPL searches (`rex`, `stats`, `where`, `timechart`).
- Spotting brute force patterns in authentication logs.
- Handling duplicate data in Splunk and filtering it safely.
- Documenting an investigation clearly.

## Author
Ammar Munawwar, Computer Science student preparing for a SOC Analyst L1 role.