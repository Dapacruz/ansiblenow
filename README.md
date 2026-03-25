# AnsibleNow

Execute Ansible playbooks automatically in response to ServiceNow incidents.

AnsibleNow polls ServiceNow for open incidents, determines the appropriate Ansible Automation Platform (AAP) job template to run based on the affected configuration item, launches the playbook, and posts status updates back to the incident as work notes — all without manual intervention.

## Table of Contents

- [How It Works](#how-it-works)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage Guide](#usage-guide)
- [CLI Arguments](#cli-arguments)
- [Logging](#logging)
- [Email Notifications](#email-notifications)
- [Database](#database)
- [Scheduling](#scheduling)
- [Project Structure](#project-structure)
- [Troubleshooting](#troubleshooting)

## How It Works

1. **Poll** — AnsibleNow queries the ServiceNow Incident table using a configurable filter.
2. **Filter** — Incidents not created by a Service Alert Rule, or already handled, are skipped.
3. **Dispatch** — Based on the incident's configuration item (CI), the matching Ansible job template is launched:
   - **Firewalls** → device state snapshot playbook
   - **Corporate routing devices** → device state snapshot playbook
   - **Store network devices** → store diagnostic report playbook
4. **Track** — The incident number is recorded in a local SQLite database to prevent duplicate executions. Running job IDs are also tracked.
5. **Update** — Work notes are posted to the incident when a playbook starts and again when it finishes, including links to the job template and job log in AAP.
6. **Notify** — On any error, the log file is emailed to the configured recipient (rate-limited to one email per 2-hour window).

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) (recommended)
- **Or**, Python >= 3.11 with `pip`
- Access to an Ansible Automation Platform (AAP) instance
- Access to a ServiceNow instance with the Incident API enabled
- An SMTP server for error notifications

## Installation

```sh
# Clone the repository
git clone https://github.com/your-org/ansiblenow.git
cd ansiblenow

# Copy and configure the environment file
cp .env.example .env
```

Edit `.env` with your environment-specific values. See [Configuration](#configuration) for details on each variable.

## Configuration

All configuration is provided via environment variables. Copy `.env.example` to `.env` and fill in the values before running.

### Ansible Automation Platform

| Variable | Description | Example |
|---|---|---|
| `ANSIBLE_USER` | AAP username | `user` |
| `ANSIBLE_PASSWORD` | AAP password | `password` |
| `ANSIBLE_URL` | Base URL of your AAP instance | `https://aap.domain.com` |
| `ANSIBLE_HOSTS_FIREWALLS_ID` | Inventory ID containing firewall hosts | `76` |
| `ANSIBLE_HOSTS_CORP_ROUTING_DEVICES_ID` | Inventory ID containing corporate routing device hosts | `75` |

### ServiceNow

| Variable | Description | Example |
|---|---|---|
| `SERVICENOW_USER` | ServiceNow username | `user` |
| `SERVICENOW_PASSWORD` | ServiceNow password | `password` |
| `SERVICENOW_URL` | Base URL of your ServiceNow instance | `https://instance.service-now.com` |
| `SERVICENOW_INCIDENT_QUERY` | Encoded query string for filtering incidents | `stateIN1,2^assignment_group=...` |
| `SERVICENOW_STORE_NETWORK_QUERY` | Encoded query prefix for the store network table | `u_store_statusANYTHING^u_store_numberSTARTSWITH` |
| `SERVICENOW_STORE_SDWAN_MIST_QUERY` | Encoded query prefix for the store information table | `u_store_statusANYTHING^u_store_numberSTARTSWITH` |
| `SERVICENOW_TEST_INCIDENT` | Incident number used when running with `--test` | `INC000000001` |

### Email Notifications

| Variable | Description | Example |
|---|---|---|
| `SMTP_SERVER` | SMTP server hostname | `smtp.domain.com` |
| `SMTP_TO` | Recipient email address | `user@domain.com` |
| `SMTP_FROM` | Sender name and address | `AnsibleNow <no-reply@domain.com>` |

### General

| Variable | Description | Example |
|---|---|---|
| `TZ` | Timezone for log and database timestamps | `America/Los_Angeles` |

## Usage Guide

### Build the Docker image

```sh
docker build -t ansiblenow .
```

### Run (standard)

```sh
docker run --rm --env-file .env -v $(pwd):/usr/src/ansiblenow ansiblenow
```

### Populate the database without executing playbooks

Use this on the first run against a live environment to seed the database with existing incidents and avoid triggering playbooks for incidents that are already open.

> **Note:** If `ansiblenow.db` does not exist when the container starts, AnsibleNow automatically runs in populate-only mode regardless of arguments.

```sh
docker run --rm --env-file .env -v $(pwd):/usr/src/ansiblenow ansiblenow python ansiblenow.py --populate-db
```

### Test against a specific incident

Executes a playbook for the incident number defined in `SERVICENOW_TEST_INCIDENT`. Useful for validating connectivity and configuration before running in production.

```sh
docker run --rm --env-file .env -v $(pwd):/usr/src/ansiblenow ansiblenow python ansiblenow.py --test
```

### Interactive shell

```sh
docker run --rm --env-file .env -itv $(pwd):/usr/src/ansiblenow ansiblenow /bin/bash
```

## CLI Arguments

| Argument | Description |
|---|---|
| `--populate-db` | Fetch incidents from ServiceNow and add them to the database without launching any playbooks. |
| `--test` | Launch a playbook for the incident in `SERVICENOW_TEST_INCIDENT`. |

Both flags can be combined. If neither is provided, AnsibleNow runs in normal production mode.

## Logging

Logs are written to `logs/ansiblenow.log` with automatic rotation:

- **Max file size:** 500 KB
- **Backup count:** 10 files

Each log line includes a timestamp and message. The `logs/` directory is mounted from the host via the Docker volume, so logs persist across container runs.

## Email Notifications

When an unhandled exception occurs, AnsibleNow emails the current log file to `SMTP_TO`. To avoid alert fatigue, notifications are suppressed for **2 hours** after the first error email. The suppression state is tracked via a `NOTIFICATIONS_SUPPRESSED` sentinel file in the working directory, which is automatically removed once the suppression window expires.

## Database

AnsibleNow uses a local SQLite database (`ansiblenow.db`) with two tables:

| Table | Purpose |
|---|---|
| `incidents` | Stores handled incident numbers to prevent duplicate playbook executions. Records older than 1 year are pruned automatically on each run. |
| `running_jobs` | Stores in-progress Ansible job IDs along with the associated incident and job template. Records are deleted when the job reaches a terminal state. |

The database file is stored in the working directory and persists across container runs via the Docker volume mount.

## Scheduling

AnsibleNow is designed to be executed on a recurring schedule (e.g., every minute via cron) rather than running as a long-lived daemon.

**Example crontab entry (runs every minute):**

```cron
* * * * * docker run --rm --env-file /path/to/.env -v /path/to/ansiblenow:/usr/src/ansiblenow ansiblenow >> /path/to/ansiblenow/logs/cron.log 2>&1
```

## Project Structure

```
ansiblenow/
├── ansiblenow.py       # Main Python script
├── Dockerfile          # Docker build file
├── requirements.txt    # Python dependencies (requests)
├── .env.example        # Example environment file
└── logs/               # Log file directory (persisted via Docker volume)
```

## Troubleshooting

**Playbooks are firing for incidents that already exist**

Run with `--populate-db` first to seed the database with all currently open incidents before switching to production mode.

**No incidents are being processed**

- Verify `SERVICENOW_INCIDENT_QUERY` returns results in ServiceNow using the table API directly.
- Confirm the incident's work notes contain the text `Incident was created using Service Alert Rule` — incidents without this string are skipped by design.
- Check `logs/ansiblenow.log` for HTTP errors or authentication failures.

**Ansible job is not launching**

- Confirm `ANSIBLE_URL`, `ANSIBLE_USER`, and `ANSIBLE_PASSWORD` are correct.
- Verify the job template ID is correct and the template is enabled in AAP.
- Check that the CI name in the incident matches a host in the target AAP inventory.

**Email notifications are not being received**

- Confirm `SMTP_SERVER`, `SMTP_TO`, and `SMTP_FROM` are set correctly.
- Check whether a `NOTIFICATIONS_SUPPRESSED` file exists in the working directory — if present and recent, notifications are being suppressed. Delete it to re-enable immediately.

**SSL warnings in the logs**

SSL verification is disabled for AAP API calls (common in environments with self-signed certificates). The `urllib3` warnings are suppressed by default. To enable SSL verification, update the `verify=False` calls in `ansiblenow.py` and ensure AAP's certificate is trusted.
