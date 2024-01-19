#!/usr/bin/env python3

"""Execute Ansible playbooks in response to ServiceNow incidents

ansiblenow.py

Author: David Cruz

Python version >= 3.11.0

Required Python packages:
    requests

Features:
    Triggers the execution of Ansible playbooks in response to ServiceNow incidents
    Adds handled incidents to a database to prevent duplicate playbook executions
    Removes incidents from the database after one year
    Adds running Ansible jobs to a database to track job status
    Removes jobs from the database after completion
    Updates incident work notes when executing playbooks and when jobs complete
    Detailed logging with file rotation
    Email notifications on errors
    Command line arguments for populating the handled incidents database only and testing
    Containerized to eliminate dependency issues
"""

import argparse
import json
import logging
import logging.handlers
import os
import re
import signal
import smtplib
import sqlite3
import sys
import time
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path

import requests

requests.packages.urllib3.disable_warnings()

script_path = os.path.dirname(os.path.abspath(__file__))
LOGGING_LEVEL = logging.INFO
NOTIFY_SUPPRESS_DURATION = 60 * 60 * 2  # 2 hours
NOTIFY_SUPPRESS_FNAME = Path(script_path, "NOTIFICATIONS_SUPPRESSED")
ANSIBLENOW_DB = Path(script_path, "ansiblenow.db")
ANSIBLENOW_LOG = Path(script_path, "logs/ansiblenow.log")
ANSIBLE_USER = os.getenv("ANSIBLE_USER")
ANSIBLE_PASSWORD = os.getenv("ANSIBLE_PASSWORD")
ANSIBLE_URL = os.getenv("ANSIBLE_URL")
ANSIBLE_HOSTS_FIREWALLS_ID = os.getenv("ANSIBLE_HOSTS_FIREWALLS_ID")
ANSIBLE_HOSTS_CORP_ROUTING_DEVICES_ID = os.getenv(
    "ANSIBLE_HOSTS_CORP_ROUTING_DEVICES_ID"
)
SERVICENOW_USER = os.getenv("SERVICENOW_USER")
SERVICENOW_PASSWORD = os.getenv("SERVICENOW_PASSWORD")
SERVICENOW_URL = os.getenv("SERVICENOW_URL")
SERVICENOW_INCIDENT_QUERY = os.getenv("SERVICENOW_INCIDENT_QUERY")
SERVICENOW_TEST_INCIDENT = os.getenv("SERVICENOW_TEST_INCIDENT")
SERVICENOW_STORE_NETWORK_QUERY = os.getenv("SERVICENOW_STORE_NETWORK_QUERY")
SERVICENOW_STORE_SDWAN_MIST_QUERY = os.getenv("SERVICENOW_STORE_SDWAN_MIST_QUERY")
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_TO = os.getenv("SMTP_TO")
SMTP_FROM = os.getenv("SMTP_FROM")

help_examples = f"""
examples:
-------------------------- EXAMPLE 1 --------------------------
> ./ansiblenow.py --populate-db

-------------------------- EXAMPLE 2 --------------------------
> ./ansiblenow.py --test
"""


def sigint_handler(signum, frame):
    sys.exit(1)


def initialize_logger():
    log_handler = logging.handlers.RotatingFileHandler(
        ANSIBLENOW_LOG, maxBytes=500000, backupCount=10
    )
    formatter = logging.Formatter("%(asctime)s - %(message)s")
    log_handler.setFormatter(formatter)
    logger = logging.getLogger()
    logger.addHandler(log_handler)
    logger.setLevel(LOGGING_LEVEL)

    return logger


def parse_args():
    parser = argparse.ArgumentParser(
        description="Incident Response Automation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=help_examples,
    )
    parser.add_argument(
        "--populate-db",
        metavar="",
        action=argparse.BooleanOptionalAction,
        help="Populate the database with incidents from ServiceNow",
    )
    parser.add_argument(
        "--test",
        metavar="",
        action=argparse.BooleanOptionalAction,
        help="Execute an Ansible playbook for a test incident",
    )

    return parser.parse_args()


def prune_database(con, cur, logger):
    # Remove incidents that are older than 1 year
    try:
        cur.execute(
            "DELETE FROM incidents WHERE insertion_date < datetime('now', 'localtime', '-1 year')"
        )
        con.commit()
    except Exception as e:
        log_and_notify(e, logger)


def insert_incident(con, cur, incident_number, logger):
    # Insert the incident into the database
    try:
        cur.execute("INSERT INTO incidents (number) VALUES (?)", (incident_number,))
        con.commit()
    except Exception as e:
        log_and_notify(e, logger)

    logger.info(f"Added incident {incident_number} to the database")


def insert_job(con, cur, job_id, incident_number, incident_sys_id, template_id, logger):
    # Insert the job ID into the database
    try:
        cur.execute(
            "INSERT INTO running_jobs (id, inc_num, inc_sys_id, ans_templ_id) VALUES (?, ?, ?, ?)",
            (job_id, incident_number, incident_sys_id, template_id),
        )
        con.commit()
    except Exception as e:
        log_and_notify(e, logger)

    logger.info(f"Added Ansible job ID {job_id} to the database")


def delete_job(con, cur, job_id, logger):
    # Remove job from the database
    try:
        cur.execute("DELETE FROM running_jobs WHERE id == ?", (job_id,))
        con.commit()
    except Exception as e:
        log_and_notify(e, logger)

    logger.info(f"Deleted Ansible job ID {job_id} from the database")


def execute_playbook(
    con, cur, ci_name, incident_number, incident_sys_id, template_id, logger
):
    payload = {
        "extra_vars": {"configuration_item": ci_name, "snow_incident": incident_number}
    }
    headers = {"Content-Type": "application/json"}

    try:
        r = requests.post(
            f"{ANSIBLE_URL}/api/v2/job_templates/{template_id}/launch/",
            data=json.dumps(payload),
            auth=(ANSIBLE_USER, ANSIBLE_PASSWORD),
            headers=headers,
            verify=False,
        )
        r.raise_for_status()
    except Exception as e:
        log_and_notify(e, logger)

    job = r.json()

    if r.status_code != 201:
        logger.error(f"Error: {r.status_code}")
        logger.error(job)

    # Add job ID to the database
    insert_job(
        con, cur, job["id"], incident_number, incident_sys_id, template_id, logger
    )

    # Add incident to the database
    insert_incident(con, cur, incident_number, logger)

    # Update incident worknotes
    template_name = re.sub(
        r"^\S+\s\|\s", "", job["summary_fields"]["job_template"]["name"]
    )
    template_url = f"{ANSIBLE_URL}/#/templates/job_template/{template_id}/details"
    job_log_url = f"{ANSIBLE_URL}/#/jobs/playbook/{job['id']}/output"
    work_notes = f"[code]Executing Ansible playbook<br><br><b>Job Template:</b> <a target='_blank' href={template_url} >{template_name}</a> | <b>Job ID:</b> <a target='_blank' href={job_log_url} >{job['id']}</a>[/code]"
    update_work_notes(incident_sys_id, work_notes, logger)

    logger.info(
        f"Executing Ansible playbook '{template_name}', for {ci_name}, in response to incident {incident_number} (job ID {job['id']})"
    )


def get_ansible_hosts(inventory_id, logger):
    try:
        r = requests.get(
            f"{ANSIBLE_URL}/api/v2/hosts/?inventory={inventory_id}&page_size=10000",
            auth=(ANSIBLE_USER, ANSIBLE_PASSWORD),
            verify=False,
        )
        r.raise_for_status()
    except Exception as e:
        log_and_notify(e, logger)

    if r.status_code != 200:
        logger.error(f"Error: {r.status_code}")
        logger.error(r.json())

    return [fw["name"] for fw in r.json()["results"]]


def get_incidents(logger):
    try:
        r = requests.get(
            f"{SERVICENOW_URL}/api/now/v1/table/incident?sysparm_display_value=true&sysparm_query={SERVICENOW_INCIDENT_QUERY}",
            auth=(SERVICENOW_USER, SERVICENOW_PASSWORD),
        )
        r.raise_for_status()
    except requests.exceptions.HTTPError as e:
        error = r.json()["error"]["message"]
        if e.response.status_code == 404 and error == "No Record found":
            return []
        else:
            log_and_notify(e, logger)
    except Exception as e:
        log_and_notify(e, logger)

    return r.json()["result"]


def get_store_net_info(store_number, logger):
    try:
        r = requests.get(
            f"{SERVICENOW_URL}/api/now/v1/table/u_network?sysparm_display_value=true&sysparm_fields=u_concept,u_router,u_switch_1,u_ip_network,u_subnet_mask,u_bb_tunnel1&sysparm_query={SERVICENOW_STORE_NETWORK_QUERY}{store_number}",
            auth=(SERVICENOW_USER, SERVICENOW_PASSWORD),
        )
        r.raise_for_status()
    except Exception as e:
        log_and_notify(e, logger)

    return r.json()["result"][0]


def get_store_info(store_number, logger):
    try:
        r = requests.get(
            f"{SERVICENOW_URL}/api/now/v1/table/u_store_information_1?sysparm_display_value=true&sysparm_fields=u_concept,u_sdwan,u_poc_wifi&sysparm_query={SERVICENOW_STORE_SDWAN_MIST_QUERY}{store_number}",
            auth=(SERVICENOW_USER, SERVICENOW_PASSWORD),
        )
        r.raise_for_status()
    except Exception as e:
        log_and_notify(e, logger)

    return r.json()["result"][0]


def get_running_jobs(cur, logger):
    # Create a list of all running jobs from the database
    try:
        jobs = [
            (row[0], row[1], row[2], row[3])
            for row in cur.execute(
                "SELECT id, inc_sys_id, inc_num, ans_templ_id FROM running_jobs"
            ).fetchall()
        ]
    except Exception as e:
        log_and_notify(e, logger)

    return jobs


def process_jobs(con, cur, jobs, logger):
    # Check the status of running jobs and handle when complete
    for job_id, sys_id, inc_num, template_id in jobs:
        try:
            r = requests.get(
                f"{ANSIBLE_URL}/api/v2/jobs/{job_id}/",
                auth=(ANSIBLE_USER, ANSIBLE_PASSWORD),
                verify=False,
            )
            r.raise_for_status()
        except Exception as e:
            log_and_notify(e, logger)

        job = r.json()

        if job["status"] != "pending" and job["status"] != "running":
            # Post worknote to the incident
            template_name = re.sub(
                r"^\S+\s\|\s", "", job["summary_fields"]["job_template"]["name"]
            )
            template_url = (
                f"{ANSIBLE_URL}/#/templates/job_template/{template_id}/details"
            )
            job_log_url = f"{ANSIBLE_URL}/#/jobs/playbook/{job_id}/output"
            work_notes = f"[code]Ansible playbook execution completed with a status of '{job['status']}'<br><br><b>Ansible Automation Platform</b><br>- <a target='_blank' href={template_url}>Open Job Template</a> ({template_name})<br>- <a target='_blank' href={job_log_url}>Open Job Log</a>[/code]"
            update_work_notes(sys_id, work_notes, logger)
            logger.info(
                f"Ansible playbook '{template_name}' execution, for incident {inc_num}, completed with a status '{job['status']}'"
            )

            # Remove job from the database
            delete_job(con, cur, job_id, logger)


def update_work_notes(incident_sys_id, work_notes, logger):
    payload = {"work_notes": work_notes}
    headers = {"Content-Type": "application/json", "Accept": "application/json"}

    try:
        r = requests.patch(
            f"{SERVICENOW_URL}/api/now/table/incident/{incident_sys_id}",
            auth=(SERVICENOW_USER, SERVICENOW_PASSWORD),
            data=json.dumps(payload),
            headers=headers,
        )
        r.raise_for_status()
    except Exception as e:
        log_and_notify(e, logger)

    if r.status_code != 200:
        logger.error(f"Error: {r.status_code}")
        logger.error(r.json())


def log_and_notify(error, logger):
    logger.exception(error)

    if not os.path.isfile(NOTIFY_SUPPRESS_FNAME):
        # Create a file to suppress notifications
        try:
            Path(NOTIFY_SUPPRESS_FNAME).touch()
        except Exception as e:
            log_and_notify(e, logger)

        # Send log file via email
        notify(logger)


def notify(logger):
    msg = EmailMessage()
    msg["To"] = SMTP_TO
    msg["From"] = SMTP_FROM
    msg["Subject"] = "AnsibleNow encountered an error"
    msg.set_content("Please see the attached log file.")
    try:
        with open(ANSIBLENOW_LOG, "rb") as f:
            msg.add_attachment(
                f.read(), filename="ansiblenow.log", maintype="text", subtype="plain"
            )
    except Exception as e:
        log_and_notify(e, logger)

    s = smtplib.SMTP(SMTP_SERVER)
    try:
        s.send_message(msg)
    except Exception as e:
        log_and_notify(e, logger)


def main():
    t1_start = time.time()

    logger = initialize_logger()

    # Ctrl+C graceful exit
    signal.signal(signal.SIGINT, sigint_handler)

    # Re-enable notifications after NOTIFY_SUPPRESS_DURATION
    try:
        if os.path.isfile(NOTIFY_SUPPRESS_FNAME):
            suppression_start = os.path.getmtime(NOTIFY_SUPPRESS_FNAME)
            duration_start = time.time() - NOTIFY_SUPPRESS_DURATION
            if suppression_start < duration_start:
                os.remove(NOTIFY_SUPPRESS_FNAME)
    except Exception as e:
        log_and_notify(e, logger)

    args = parse_args()

    # If the database does not exist, create and populate only
    try:
        if not os.path.isfile(ANSIBLENOW_DB):
            args.populate_db = True
            logger.info(
                "Ansible execution disabled, creating and populating the database only"
            )
    except Exception as e:
        log_and_notify(e, logger)

    try:
        con = sqlite3.connect(ANSIBLENOW_DB)
        cur = con.cursor()
        cur.execute(
            "CREATE TABLE if not exists incidents (number TEXT, insertion_date DATETIME DEFAULT CURRENT_TIMESTAMP)"
        )
        cur.execute(
            "CREATE TABLE if not exists running_jobs (id TEXT, inc_num TEXT, inc_sys_id TEXT, ans_templ_id TEXT, insertion_date DATETIME DEFAULT CURRENT_TIMESTAMP)"
        )
    except Exception as e:
        log_and_notify(e, logger)

    # Remove incidents, from the database, after one year
    prune_database(con, cur, logger)

    # Process running jobs
    running_jobs = get_running_jobs(cur, logger)
    if running_jobs:
        process_jobs(con, cur, running_jobs, logger)

    # Fetch incidents from ServiceNow
    incidents = get_incidents(logger)

    # Create a list of all handled incidents from the database
    try:
        handled_incidents = [
            row[0] for row in cur.execute("SELECT number FROM incidents").fetchall()
        ]
    except Exception as e:
        log_and_notify(e, logger)

    # Fetch a list of all firewalls in Ansible
    firewalls = get_ansible_hosts(ANSIBLE_HOSTS_FIREWALLS_ID, logger)

    # Fetch a list of all Cisco corporate routing devices in Ansible
    corp_routing_devices = get_ansible_hosts(
        ANSIBLE_HOSTS_CORP_ROUTING_DEVICES_ID, logger
    )

    # Handle new incidents
    for incident in incidents:
        if ci_name := incident.get("cmdb_ci"):
            ci_name = ci_name.get("display_value", "").lower()

        if store_number := incident.get("u_store"):
            store_number = store_number.get("display_value")

        incident_number = incident.get("number")
        incident_sys_id = incident.get("sys_id")
        work_notes = incident.get("work_notes")
        short_description = incident.get("short_description")

        # DEBUG: Execute Ansible playbook on test incident
        if args.test and incident_number == SERVICENOW_TEST_INCIDENT:
            execute_playbook(
                con, cur, ci_name, incident_number, incident_sys_id, 177, logger
            )
            continue

        if incident_number in handled_incidents:
            # Skip incidents that have already been handled
            continue
        elif "Incident was created using Service Alert Rule" not in work_notes:
            # Skip incidents that were not created by a Service Alert Rule
            continue

        if args.populate_db:
            # Add incident to the database
            insert_incident(con, cur, incident_number, logger)
            continue

        # Execute Ansible playbooks
        if ci_name in firewalls:
            # Attach device state snapshot to incident
            execute_playbook(
                con, cur, ci_name, incident_number, incident_sys_id, 177, logger
            )
        elif ci_name in corp_routing_devices:
            # Attach device state snapshot to incident
            execute_playbook(
                con, cur, ci_name, incident_number, incident_sys_id, 178, logger
            )
        elif store_number:
            logger.info(
                f"Incident {incident_number} is related to store number {store_number}"
            )

            # Fetch store network info
            # TODO: Remove; no need to collect this info any longer; now done in the playbook
            store_net_info = get_store_net_info(store_number, logger)
            store_router = store_net_info.get("u_router")
            store_switch = store_net_info.get("u_switch_1")
            store_subnet = store_net_info.get("u_ip_network")
            store_subnet_mask = store_net_info.get("u_subnet_mask")
            store_bgp_ip = store_net_info.get("u_bb_tunnel1")
            logger.info(
                f"Incident: {incident_number} | Router: {store_router} | Switch: {store_switch} | Subnet: {store_subnet} | Subnet Mask: {store_subnet_mask} | Store BB Tunnel IP: {store_bgp_ip}"
            )

            # Fetch store info
            # TODO: Remove; no need to collect this info any longer; now done in the playbook
            store_info = get_store_info(store_number, logger)
            store_concept = store_info.get("u_concept")
            sdwan_store = store_info.get("u_sdwan")
            mist_store = store_info.get("u_poc_wifi")
            logger.info(
                f"Incident: {incident_number} | Store Concept: {store_concept} | SDWAN: {sdwan_store} | Mist: {mist_store}"
            )

            # Attach diagnostic report to incident
            execute_playbook(
                con, cur, ci_name, incident_number, incident_sys_id, 179, logger
            )

    cur.close()
    con.close()

    t1_stop = time.time()
    logger.info(f"Execution time: {t1_stop - t1_start :.3f} seconds")


if __name__ == "__main__":
    main()
