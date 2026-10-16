# Splunk Log Investigation: SSH Brute Force Attempt

**Dataset:** Splunk tutorial sample data (sourcetype `www1/secure`, Linux authentication logs)
**Analyst:** Ammar Munawwar
**Verdict:** Brute force attempt, unsuccessful | **Risk:** Medium

## Summary
I found a large number of failed login attempts from multiple IP addresses against common account names such as root, admin and operator. The top attacker, `87[.]194[.]216[.]51`, made 948 attempts. No successful login was found, so the attack did not succeed.

## Key Findings
1. IP `87[.]194[.]216[.]51` made **948 failed password attempts**, the highest in the dataset.
2. It tried **140 different usernames**, mostly common system accounts (root, operator, admin, mail, db), which points to a dictionary-style attack.
3. Attempts came in **short daily bursts** (7 to 14 Oct, peak about 220 in one hour on 11 Oct) with no activity in between, which suggests automation.
4. **No successful login** ("Accepted password") was found from this IP.
5. AbuseIPDB shows a 0% confidence score with no reports. The ISP is Telefonica UK (O2), a fixed line connection in the UK. A clean score does not prove the IP is harmless.

## Other Attackers
I compared failed and successful logins for every IP with more than 100 failed attempts. None of them had a successful login.
# Splunk Log Investigation: SSH Brute Force Attempt

**Dataset:** Splunk tutorial sample data (sourcetype `www1/secure`, Linux authentication logs)
**Analyst:** Ammar Munawwar
**Verdict:** Brute force attempt, unsuccessful | **Risk:** Medium

## Summary
I found a large number of failed login attempts from multiple IP addresses against common account names such as root, admin and operator. The top attacker, `87[.]194[.]216[.]51`, made 948 attempts. No successful login was found, so the attack did not succeed.

## Key Findings
1. IP `87[.]194[.]216[.]51` made **948 failed password attempts**, the highest in the dataset.
2. It tried **140 different usernames**, mostly common system accounts (root, operator, admin, mail, db), which points to a dictionary-style attack.
3. Attempts came in **short daily bursts** (7 to 14 Oct, peak about 220 in one hour on 11 Oct) with no activity in between, which suggests automation.
4. **No successful login** ("Accepted password") was found from this IP.
5. AbuseIPDB shows a 0% confidence score with no reports. The ISP is Telefonica UK (O2), a fixed line connection in the UK. A clean score does not prove the IP is harmless.

## Other Attackers
I compared failed and successful logins for every IP with more than 100 failed attempts. None of them had a successful login.

## Searches Used
```
1. Top attacking IPs
index=main sourcetype="www1/secure" "Failed password" | where host=="tutorial" | rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)" | stats count by src_ip | sort - count

2. Usernames tried by the top IP
index=main sourcetype="www1/secure" "Failed password" | where host=="tutorial" | search "87.194.216.51" | rex "for (invalid user )?(?<user>\S+) from" | stats count by user | sort - count

3. Successful logins from the top IP
index=main sourcetype="www1/secure" "Accepted password" | where host=="tutorial" | search "87.194.216.51"

4. Failed vs successful logins per IP
index=main sourcetype="www1/secure" ("Failed password" OR "Accepted password") | where host=="tutorial" | rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)" | eval result=if(searchmatch("Accepted password"),"success","failed") | stats count(eval(result=="failed")) as failed count(eval(result=="success")) as success by src_ip | where failed>100 | sort - failed

5. Attack timeline
index=main sourcetype="www1/secure" "Failed password" | where host=="tutorial" | search "87.194.216.51" | timechart span=1h count
```

## Limitations
- This is sample data, so the activity is not a real incident.
- The dataset was loaded twice, so I filtered with `where host=="tutorial"` to avoid double counts.
- The searches only cover password logins, not other methods such as SSH keys.
- AbuseIPDB data reflects today's reputation, not necessarily the reputation at the time of the logs.

## Recommended Actions
1. Block the IP at the firewall.
2. Enforce SSH key login or MFA and disable password login for root.
3. Add rate limiting or fail2ban against repeated failed logins.
4. Alert on more than N failed logins per IP per hour, and on any success after many failures.
## Searches Used
```
1. Top attacking IPs
index=main sourcetype="www1/secure" "Failed password" | where host=="tutorial" | rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)" | stats count by src_ip | sort - count

2. Usernames tried by the top IP
index=main sourcetype="www1/secure" "Failed password" | where host=="tutorial" | search "87.194.216.51" | rex "for (invalid user )?(?<user>\S+) from" | stats count by user | sort - count

3. Successful logins from the top IP
index=main sourcetype="www1/secure" "Accepted password" | where host=="tutorial" | search "87.194.216.51"

4. Failed vs successful logins per IP
index=main sourcetype="www1/secure" ("Failed password" OR "Accepted password") | where host=="tutorial" | rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)" | eval result=if(searchmatch("Accepted password"),"success","failed") | stats count(eval(result=="failed")) as failed count(eval(result=="success")) as success by src_ip | where failed>100 | sort - failed

5. Attack timeline
index=main sourcetype="www1/secure" "Failed password" | where host=="tutorial" | search "87.194.216.51" | timechart span=1h count
```

## Limitations
- This is sample data, so the activity is not a real incident.
- The dataset was loaded twice, so I filtered with `where host=="tutorial"` to avoid double counts.
- The searches only cover password logins, not other methods such as SSH keys.
- AbuseIPDB data reflects today's reputation, not necessarily the reputation at the time of the logs.

## Recommended Actions
1. Block the IP at the firewall.
2. Enforce SSH key login or MFA and disable password login for root.
3. Add rate limiting or fail2ban against repeated failed logins.
4. Alert on more than N failed logins per IP per hour, and on any success after many failures.