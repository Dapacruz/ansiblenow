AnsibleNow
===========
Execute Ansible playbooks in response to ServiceNow incidents

### Features
- Triggers the execution of Ansible playbooks in response to ServiceNow incidents
- Adds handled incidents to a database to prevent duplicate playbook executions
- Removes incidents from the database after one year
- Adds running Ansible jobs to a database to track job status
- Removes jobs from the database after completion
- Updates incident work notes when executing playbooks and when jobs complete
- Detailed logging with file rotation
- Email notifications on errors
- Command line arguments for populating the handled incidents database only and testing
- Containerized to eliminate dependency issues
### Usage Guide
#### Build
```sh
docker build -t ansiblenow .
```
#### Test
```sh
docker run --env-file .env -v $(pwd):/usr/src/ansiblenow ansiblenow python ansiblenow.py --test
```
#### Test Interactively
```sh
docker run --env-file .env -itv $(pwd):/usr/src/ansiblenow ansiblenow /bin/bash
```
#### Run
```sh
docker run --env-file .env -v $(pwd):/usr/src/ansiblenow ansiblenow
```

### Main Files
- `ansiblenow.py`: Main Python script
- `Dockerfile`: Docker build file
- `requirements.txt`: Python dependencies
- `.env.example`: Example environment file
