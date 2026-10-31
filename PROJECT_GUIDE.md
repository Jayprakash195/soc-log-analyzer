# Project Guide: Resume and Interview Preparation

Use these claims only after you have run the application and understand the implementation. The web application and its API tests should be verified locally before describing them as tested.

## Resume entry

**SOC Log Analyzer: SSH Attack Detection and Reporting Web App (Python, Flask, HTML, CSS, JavaScript)**

- Built a Python log-analysis engine to parse Linux SSH authentication logs and detect brute force, password spraying, and successful logins following repeated failures.
- Integrated the existing detection engine with a Flask web API and responsive dashboard supporting log uploads, finding filters, charts, and downloadable JSON/CSV/HTML reports.
- Implemented sliding-window evidence, severity ratings, MITRE ATT&CK mappings, input validation, and automated unit tests.

## 30-second explanation for interviews

"I developed a Python-based SOC Log Analyzer that helps triage Linux SSH authentication logs. Its detection engine parses failed and successful login events, groups activity by source IP and username, and applies configurable rules for brute force, password spraying, and suspicious successful logins after repeated failures. I connected that engine to a Flask web application so an analyst can upload a log, review evidence and charts, and download reports. The findings are indicators for investigation, not proof of compromise, and I use tests to validate the detection logic."

## Questions you may be asked

| Question | Key points to answer |
|---|---|
| Why build this when SIEMs exist? | To understand detection logic and automate basic log triage; similar rules can be implemented in Splunk SPL or Wazuh. |
| How do brute force and password spraying differ? | Brute force: many attempts against a small number of users. Spraying: attempts spread across many usernames. |
| Why count failures before a success? | Failures after a successful login cannot explain how that password was obtained. The correlation uses earlier events for the same IP and username. |
| What is a sliding window? | It measures the maximum count of failed attempts inside any configured time window. |
| How does the browser connect to Python? | The frontend sends a multipart file upload to Flask; Flask calls the same analysis engine used by the CLI and returns structured JSON. |
| How do you reduce false positives? | Tune thresholds, understand expected behavior, add allowlists where appropriate, and correlate with other telemetry. |
| What are the limitations? | Supported SSH message formats only, fixed default thresholds, no durable multi-user report storage, and possible low-and-slow misses. |
| What would you improve next? | Windows log support, richer detection rules, authenticated access, persistent report storage, alerting, and live monitoring. |

## False-positive decisions

- A user who mistypes a password twice and then logs in is below the five-failure correlation threshold.
- A source with only three failures is below the default brute-force threshold and may not meet the spraying rule.
- Failures that occur after a successful login are not counted as earlier failures in the success-after-failures detection.

## Safety and operational notes

- Analyze only logs you own or are authorized to inspect.
- Do not describe a detection as confirmed compromise without corroborating evidence.
- Do not claim deployment or web/API tests passed until you have run and verified them.
- The demo stores report references in memory and writes reports to temporary storage. This is not durable production storage.
