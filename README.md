# Easy-wazuh - Wazuh Docker PoC Installer

Setup a Wazuh Docker PoC service easily on one Debian Docker host or VM.

## Scope

This project installs a **Wazuh Docker stack on one Docker host/VM** for a proof of concept (PoC), lab, or evaluation environment.

The stack uses three separate Wazuh component images and containers on the same Docker host/VM:

- Wazuh manager
- Wazuh indexer
- Wazuh dashboard

This separation is intentional. It keeps the Wazuh roles, logs, volumes, and configuration boundaries visible from the first PoC. It also makes future analysis easier if the customer later wants to move, scale, or redesign one layer independently.

The installer lets the user choose between the official Wazuh Docker `single-node` and `multi-node` compose stacks. The default and recommended choice is `multi-node`, because it is closer to a scalable architecture while still running on one Docker host/VM.

Single-node uses the official service names:

```text
wazuh.indexer
wazuh.manager
wazuh.dashboard
```

Multi-node uses clearer numbered FQDN service names generated from the internal TLS DNS suffix:

```text
wazuh-indexer01.<suffix>
wazuh-indexer02.<suffix>
wazuh-indexer03.<suffix>
wazuh-manager01.<suffix>
wazuh-manager02.<suffix>
wazuh-dashboard01.<suffix>
nginx
```

## Disclaimer

<p><strong><font color="red">Wazuh one Docker host/VM proof of concept only. It is not intended for production use.</font></strong></p>

Before designing or deploying a production Wazuh environment, you must evaluate the expected log transaction rate, usually expressed as events/logs per second, the required processing load, retention period, indexed data volume, number of agents, alerting use cases, and peak ingestion scenarios.

In production, Wazuh components should be separated so each layer can absorb the required load:

- Wazuh manager nodes for agent connections, event analysis, rules, and active response.
- Wazuh indexer nodes for indexing, search, storage, and retention.
- Wazuh dashboard nodes for user access and visualization.

This one Docker host/VM setup does not provide high availability, workload distribution across machines, or the resilience expected from a production Wazuh deployment. Separating components makes it possible to observe, tune, and later redesign each layer independently, but it does not create a Wazuh cluster by itself.

## Scaling and migration

This installer uses three separate Wazuh images and containers because that matches the main Wazuh roles:

```text
wazuh/wazuh-indexer    -> indexer container
wazuh/wazuh-manager    -> manager container
wazuh/wazuh-dashboard  -> dashboard container
```

This is useful for a future migration because each role already has its own container, configuration, logs, and volumes. However, scaling is still a separate architecture task.

Moving the whole stack to another Docker VM is a controlled migration task: preserve the Docker volumes, mounted configuration, certificates, and public FQDN behavior.

Splitting the roles across several VMs is not a simple container move. It requires new DNS/FQDN planning, certificates, firewall rules, Wazuh manager/indexer/dashboard configuration changes, and data migration planning.

Moving to Kubernetes is also a dedicated project. It requires Kubernetes-native design for persistent storage, Secrets, ConfigMaps, Services, Ingress or load balancers, health checks, resource limits, and certificate management.

In short, this PoC layout prepares clean role separation, but production scaling requires a distributed Wazuh design and should follow the official Wazuh architecture guidance.

## Prerequisites

- A Debian 13 machine, or an existing Docker environment correctly sized for a one Docker host/VM Wazuh PoC.
- A user account with sudo privileges.
- A stable internet connection for Docker image downloads and Wazuh image pulls.
- Network access from the Wazuh server to the endpoints you want to monitor.
- Network access from monitored endpoints to the Wazuh manager ports.

## Machine specifications

For a simple one Docker host/VM Wazuh PoC installation, use at least:

```text
CPU:      4 vCPU
RAM:      8 GB
Disk:     50 GB free
OS:       Debian 13, 64-bit
Network:  Static IP address recommended
```

For a more comfortable lab or small internal PoC deployment:

```text
CPU:      4 to 8 vCPU
RAM:      16 GB
Disk:     100 GB free
OS:       Debian 13, 64-bit
Network:  Static IP address or stable DNS name
```

For a PoC expected to evolve with more agents, longer retention, or heavier event volume:

```text
CPU:      8 vCPU or more
RAM:      16 to 32 GB
Disk:     500 GB or more, preferably SSD/NVMe
OS:       Debian 13, 64-bit
Network:  Static IP address and DNS record
```

The official Wazuh Docker documentation gives the baseline for a single-node stack as 4 CPU cores, 8 GB RAM, and 50 GB disk. Plan more disk space if you keep logs and security events for a long time. These profiles are PoC-oriented starting points, not production sizing guidance.

The installer performs a preflight resource check before package installation, Docker pulls, certificate generation, or Compose startup. Defaults are 2 vCPU minimum with a warning below 4 vCPU, 8 GB RAM and 50 GB free disk for single-node, and 2 vCPU minimum with a warning below 4 vCPU, 16 GB RAM and 100 GB free disk for multi-node, with a disk warning below 500 GB. These are minimum guardrails; the recommended multi-node lab profile above remains 500 GB or more when retention or alert volume is uncertain. For exceptional lab troubleshooting only, override with `EASY_WAZUH_SKIP_RESOURCE_CHECK=yes` or adjust `EASY_WAZUH_MIN_VCPU`, `EASY_WAZUH_RECOMMENDED_VCPU`, `EASY_WAZUH_MIN_MEMORY_GB_SINGLE_NODE`, `EASY_WAZUH_MIN_MEMORY_GB_MULTI_NODE`, `EASY_WAZUH_MIN_MEMORY_GB`, `EASY_WAZUH_MIN_DISK_FREE_GB_SINGLE_NODE`, `EASY_WAZUH_MIN_DISK_FREE_GB_MULTI_NODE`, `EASY_WAZUH_MIN_DISK_FREE_GB`, or `EASY_WAZUH_RECOMMENDED_DISK_FREE_GB`.

## Official documentation

Official Wazuh documentation:

<https://documentation.wazuh.com/current/>

The official Wazuh Docker deployment documentation is available here:

<https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html>

## Installation

On the Debian 13 machine, either clone this repository:

```bash
git clone https://github.com/cedricdicesare/Easy-wazuh.git
cd Easy-wazuh
```

It is also possible to copy only the content of `easy-wazuh-bootstrap.sh` into a new script file on the Debian 13 machine.

```bash
nano easy-wazuh-bootstrap.sh
```

Make the script executable:

```bash
chmod +x easy-wazuh-bootstrap.sh
```

Run the installer with sudo:

```bash
sudo ./easy-wazuh-bootstrap.sh
```

The installer asks for the dashboard FQDN or IP address that clients will use to reach the Wazuh VM. This value is printed at the end as the Wazuh dashboard URL. For repeatable test deployments, you can provide it non-interactively:

```bash
sudo WAZUH_PUBLIC_FQDN=wazuh.example.com ./easy-wazuh-bootstrap.sh
```

This value is used for the dashboard URL shown to users and agents. Internal container-to-container traffic uses the service names selected by the deployment mode.

If the VM hostname has no domain, for example `VM-Wazuh`, the installer builds a default dashboard FQDN by appending the default DNS suffix:

```text
VM-Wazuh.local
```

You can change that suffix for client deployments:

```bash
sudo WAZUH_PUBLIC_DNS_SUFFIX=customer.example ./easy-wazuh-bootstrap.sh
```

At the end of the deployment, the installer prints the detected server FQDN, detected server IP, and the exact dashboard URL to open in the browser.

At startup, the script asks which installation mode to use:

```text
1) Fresh Debian installation - install Docker and prerequisites
2) Existing Docker environment - keep current Docker installation
```

The script then asks which Wazuh Docker deployment mode to use:

```text
1) single-node - lab/small PoC on one Docker host
2) multi-node - recommended default for scalable Wazuh Docker deployments
```

Pressing `Enter` selects `multi-node`.

The script asks for confirmation before continuing with the selected installation mode and deployment mode. It also asks for a final confirmation before starting the Wazuh containers. The script explicitly reminds the user that this is a one Docker host/VM PoC deployment, not a production deployment.

In fresh Debian mode, the script installs Docker, configures the Wazuh indexer kernel requirement, clones the official Wazuh Docker repository, generates self-signed certificates, starts the selected Wazuh Docker stack, and prints the access information at the end.

In existing Docker mode, the script checks that Docker and the Docker Compose plugin are already available before continuing. It does not remove or reinstall Docker packages.

## FQDN and certificates

The public FQDN or IP address is used for the dashboard access URL and the generated dashboard certificate configuration. The script validates the value and warns if the FQDN does not resolve to the detected VM IP address.

For repeatable VM tests, create or update DNS before deployment, or pass the expected name explicitly:

```bash
sudo WAZUH_PUBLIC_FQDN=wazuh.lab.example ./easy-wazuh-bootstrap.sh
```

DNS requirements:

```text
wazuh.lab.example  A/AAAA  <WAZUH_VM_IP>
```

This is the only DNS record required by this PoC Docker deployment. Use the customer's real FQDN and VM IP address. The selected FQDN is what users enter in their browser and what agents can use to reach the Wazuh manager ports on the VM.

Internal Wazuh component traffic stays inside the Docker network. In single-node mode, the installer keeps the official Wazuh Docker service names. In multi-node mode, the installer rewrites the official stack to use numbered FQDN service names such as `wazuh-indexer01.local`, `wazuh-manager01.local`, and `wazuh-dashboard01.local`.

The Wazuh certificate generator requires DNS values with a domain suffix. For multi-node, the script asks for an internal TLS DNS suffix after detecting the host FQDN. By default, it uses the domain part of the VM hostname when available, otherwise it uses `local`.

For example, with suffix `lab.example`, the internal multi-node names are:

```text
wazuh-indexer01.lab.example
wazuh-indexer02.lab.example
wazuh-indexer03.lab.example
wazuh-manager01.lab.example
wazuh-manager02.lab.example
wazuh-dashboard01.lab.example
```

The suffix can also be provided non-interactively:

```bash
sudo WAZUH_INTERNAL_DNS_SUFFIX=lab.example WAZUH_PUBLIC_FQDN=wazuh.lab.example ./easy-wazuh-bootstrap.sh
```

These internal names are Docker service names inside the generated compose stack for this one-host PoC. They do not require public DNS records unless the deployment is redesigned later across multiple VMs.

If certificates already exist under `/opt/wazuh/wazuh-docker/<single-node-or-multi-node>/config/wazuh_indexer_ssl_certs`, the script keeps them only when they match the selected dashboard host metadata. If you change the dashboard FQDN/IP between runs, move the existing certificate directory away before generating new certificates.

## Custom TLS certificates

The bootstrap creates the initial Wazuh certificates with the official Wazuh certificate tooling. Browsers can warn on these self-signed certificates until the issuing CA is trusted by the client workstation.

Use `certificate-installer.sh` after bootstrap when an administrator already has a third-party PEM certificate and private key, such as a wildcard certificate, an internal PKI certificate, a public CA certificate, or a certificate dedicated to the Wazuh service. The script installs certificates only on exposed HTTPS endpoints:

```text
Dashboard HTTPS  https://<wazuh-fqdn>:443
Wazuh API        https://<wazuh-fqdn>:55000  optional, explicit choice only
```

`wazuh-certs-tool.sh` remains the Wazuh PKI generation tool. `certificate-installer.sh` is only an installer for existing third-party certificates on exposed endpoints. It does not replace `root-ca.pem`, indexer certificates, Filebeat certificates, manager-to-indexer certificates, cluster certificates, or internal OpenSearch TLS material.

The installer validates the certificate, private key, expiration, certificate/key match, SAN coverage, wildcard coverage, and IP SANs before changing files. For the API, it also checks the public endpoint and internal names used by Dashboard or orchestrator API clients before any backup or modification. Passphrase-protected private keys and `.p12`/`.pfx` files are refused in V1; export certificate/fullchain and key as PEM first.

Before replacement, backups are written under:

```text
/opt/wazuh/backups/certificates/YYYYMMDD-HHMMSS/
```

The script restores previous files and permissions and restarts only the targeted Compose service if installation or TLS verification fails. It never runs Docker volume deletion, stack-wide restart, `docker compose down -v`, or trust-store changes on client workstations.

A certificate signed by an internal PKI removes browser warnings only when that PKI is trusted by the client workstation. If the API certificate is signed by a CA not already known by the orchestrator, update `wazuh_api_ca_file`; do not disable TLS verification.

## Docker safety checks

The installer is designed to avoid damaging an existing Docker host.

It does **not** run destructive Docker cleanup commands such as:

```bash
docker system prune
docker volume prune
docker compose down -v
```

If `Fresh Debian installation` mode is selected but Docker is already installed and containers or images exist, the script stops before modifying Docker packages. This prevents an accidental fresh-install path from impacting existing workloads.

If `Existing Docker environment` mode is selected, the script keeps the current Docker installation and only checks that `docker` and `docker compose` are available.

Before starting Wazuh, the script checks whether the default Wazuh ports are already in use:

```text
443    Wazuh dashboard HTTPS
1514   Wazuh agent events TCP
1515   Wazuh agent enrollment TCP
514    Syslog UDP
55000  Wazuh server API HTTPS
9200   Wazuh indexer API HTTPS
```

If one of these ports is already used by another service or container, the script stops instead of replacing or breaking the existing workload.

If containers with `wazuh` in their name already exist, the script warns the user and asks for confirmation before continuing.

By default, the installer uses Wazuh `v4.14.5`, matching the current official Docker documentation when this project was written. To install another Wazuh Docker tag:

```bash
sudo WAZUH_VERSION=v4.14.5 ./easy-wazuh-bootstrap.sh
```

## Updating Docker images without losing data

**Before any update, make a complete snapshot of the Debian machine.** This is strongly recommended so you can restore the full Wazuh installation if the update fails.

Wazuh data, configuration, certificates, indexed events, and dashboard data are stored in Docker volumes and mounted files under `/opt/wazuh/wazuh-docker/single-node`. A normal container update recreates containers but keeps these persistent resources.

To update within the same checked-out Wazuh Docker version:

```bash
cd /opt/wazuh/wazuh-docker/single-node
sudo docker compose pull
sudo docker compose up -d
```

Then check the container status:

```bash
sudo docker compose ps
```

Do not use the following commands unless you intentionally want to delete Wazuh data:

```bash
sudo docker compose down -v
sudo docker volume prune
sudo docker system prune --volumes
```

The `-v` and `--volumes` options remove Docker volumes. Removing volumes can delete Wazuh configuration, certificates, agents, indexed events, dashboard data, and other persistent content.

## Web interface URL

After installation, the Wazuh dashboard is available at:

```text
https://<dashboard-fqdn-or-ip>
```

If the public FQDN is not available or not resolvable from your browser, use the server IP address instead:

```text
https://<server-ip>
```

The official single-node Docker Compose configuration exposes the dashboard on HTTPS port `443`.

The installer prints the final dashboard URL with `https://` at the end of the run, together with the detected server FQDN and IP address.

## Agent deployment with Ansible

Use `Deploy_Wazuh-Agent-Ansible.sh` to generate an Ansible inventory and playbook for deploying Wazuh agents on Linux endpoints.

Run it interactively:

```bash
./Deploy_Wazuh-Agent-Ansible.sh
```

The script asks for the Wazuh manager FQDN that agents will use. The value must include the domain:

```text
wazuh.customer.example
```

An IP address or a short hostname such as `wazuh` is intentionally rejected. Agents need a stable FQDN that resolves to the Wazuh server or to the load-balanced agent endpoint.

Generated files:

```text
ansible-wazuh-agent-deploy/
  deploy-wazuh-agent.yml
  inventory.ini
  group_vars/wazuh_agents.yml
```

Edit `inventory.ini` and add Linux endpoints under `[wazuh_agents]`, then run:

```bash
ansible-playbook -i ansible-wazuh-agent-deploy/inventory.ini ansible-wazuh-agent-deploy/deploy-wazuh-agent.yml
```

Non-interactive example:

```bash
WAZUH_MANAGER_FQDN=wazuh.customer.example \
ANSIBLE_PROJECT_DIR=./customer-wazuh-agents \
RUN_ANSIBLE_PLAYBOOK=no \
./Deploy_Wazuh-Agent-Ansible.sh
```

Optional variables:

```bash
WAZUH_AGENT_GROUP=linux
WAZUH_DISABLE_REPO_AFTER_INSTALL=yes
```

The generated playbook follows the official Linux package deployment flow: it configures the Wazuh package repository, installs `wazuh-agent` with `WAZUH_MANAGER=<fqdn>`, enables and starts the `wazuh-agent` service, then prints the agent status.

Network and security requirements:

- the Ansible control host must have SSH access to endpoints
- endpoints must resolve the Wazuh manager FQDN
- endpoints must reach the Wazuh server on TCP `1514` and TCP `1515`
- do not store SSH passwords or enrollment secrets in plain text inventory files
- use Ansible Vault for secrets if enrollment passwords or privileged credentials are needed

## Ports

The default Wazuh single-node Docker deployment exposes these ports:

```text
443    Wazuh dashboard HTTPS
1514   Wazuh agent events TCP
1515   Wazuh agent enrollment TCP
514    Syslog UDP
55000  Wazuh server API HTTPS
9200   Wazuh indexer API HTTPS
```

No port needs to be added to the dashboard URL with the default Wazuh Docker Compose configuration:

```text
https://<public-fqdn-or-ip>
```

Only specify a port if you changed the Docker Compose port mapping manually.

## Integrating an existing syslog source

Wazuh can receive syslog messages from existing network equipment, servers, firewalls, switches, routers, or a central syslog relay.

In this Docker PoC stack, UDP port `514` is published by the Wazuh manager container. The syslog source must send logs to the Wazuh dashboard FQDN/IP shown at the end of the installer, on UDP port `514`.

Example target from a syslog sender:

```text
Destination host: <wazuh-dashboard-fqdn-or-ip>
Destination port: 514
Protocol:         UDP
Format:           syslog / RFC3164 or RFC5424 depending on the source
```

Before enabling syslog ingestion, confirm the client-approved source IP ranges. Do not accept syslog from untrusted networks.

### Wazuh manager configuration

Save a copy of the current Wazuh manager configuration first:

```bash
sudo cp -a /opt/wazuh/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf \
  /opt/wazuh/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf.bak.$(date +%Y%m%d%H%M%S)
```

For single-node, edit:

```bash
sudo nano /opt/wazuh/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf
```

For multi-node, configure the manager node that will receive syslog traffic. Depending on the design, this can be the master or one or more workers:

```bash
sudo nano /opt/wazuh/wazuh-docker/multi-node/config/wazuh_cluster/wazuh_manager.conf
sudo nano /opt/wazuh/wazuh-docker/multi-node/config/wazuh_cluster/wazuh_worker.conf
```

Add a syslog `<remote>` block inside `<ossec_config>`, next to the existing `<remote>` block:

```xml
  <remote>
    <connection>syslog</connection>
    <port>514</port>
    <protocol>udp</protocol>
    <allowed-ips>192.0.2.10</allowed-ips>
    <local_ip>0.0.0.0</local_ip>
  </remote>
```

Replace `192.0.2.10` with the real syslog sender IP address. Add one `<allowed-ips>` entry per trusted sender or subnet if needed:

```xml
    <allowed-ips>192.0.2.10</allowed-ips>
    <allowed-ips>198.51.100.0/24</allowed-ips>
```

Use TCP only if the sender is explicitly configured for TCP syslog and the Docker Compose port mapping also publishes TCP `514`. The default Easy-wazuh/Wazuh Docker mapping is UDP `514`.

### Restart Wazuh manager

Single-node:

```bash
sudo docker compose -f /opt/wazuh/wazuh-docker/single-node/docker-compose.yml up -d --force-recreate wazuh.manager
```

For the exact manager service name in the selected stack, run:

```bash
sudo docker compose -f /opt/wazuh/wazuh-docker/single-node/docker-compose.yml config --services
```

Multi-node:

```bash
sudo docker compose -f /opt/wazuh/wazuh-docker/multi-node/docker-compose.yml up -d --force-recreate <manager-service-name>
```

Replace `<manager-service-name>` with the manager service that receives syslog. In multi-node this can be a FQDN service name such as `wazuh-manager01.local` or `wazuh-manager02.local`, depending on the suffix selected during deployment.

### Firewall and Docker filtering

Allow UDP `514` only from approved syslog sender networks. If using the `DOCKER-USER` filtering approach documented below, add the syslog source subnet to the UDP `514` allow rule:

```bash
sudo iptables -I DOCKER-USER 5 -i <EXTERNAL_INTERFACE> -p udp --dport 514 -s <SYSLOG_SUBNET> -j ACCEPT
```

Keep the final UDP `514` drop rule for all other sources.

### Validation

From a Linux syslog sender, send a test message:

```bash
logger -n <wazuh-dashboard-fqdn-or-ip> -P 514 -d "easy-wazuh syslog test"
```

Follow the manager logs:

```bash
sudo docker compose -f /opt/wazuh/wazuh-docker/single-node/docker-compose.yml logs -f wazuh.manager
```

Check alerts in the indexer:

```bash
curl -sk -u admin:SecretPassword "https://localhost:9200/_cat/indices/wazuh-alerts-*?v"
```

Then search the Wazuh dashboard for the test message or for events coming from the syslog source IP.

If no event appears, check:

- the sender really sends to UDP `514`
- the VM firewall and `DOCKER-USER` rules allow the sender IP
- the Docker Compose file publishes `514/udp`
- the Wazuh manager config contains `<connection>syslog</connection>`
- the manager container was recreated after the config change
- the syslog format has a decoder/rule that creates visible alerts

## Fixing missing alerts index template

If the dashboard shows this error after login:

```text
[Alerts index pattern] No template found for the selected index-pattern title [wazuh-alerts-*]
```

the dashboard index pattern exists, but the Wazuh alerts template or first alert
indices have not been loaded into the indexer yet.

The installer now validates Filebeat output, uploads the Wazuh ingest pipelines,
uploads the alerts index template, and checks that the template matching
`wazuh-alerts-*` exists before reporting a successful installation.

The installer validates Filebeat output inside the manager container because
Wazuh Docker can initialize `/etc/filebeat/filebeat.yml` from the
`single-node_filebeat_etc` Docker volume.

For an existing single-node deployment, run the following commands from the Wazuh VM:

```bash
COMPOSE=/opt/wazuh/wazuh-docker/single-node/docker-compose.yml
MANAGER_CONTAINER="$(sudo docker compose -f "$COMPOSE" ps -q wazuh.manager)"
sudo docker exec "$MANAGER_CONTAINER" filebeat test output
sudo docker exec "$MANAGER_CONTAINER" filebeat setup --pipelines
sudo docker exec "$MANAGER_CONTAINER" filebeat setup --index-management -E output.logstash.enabled=false
curl -sk -u admin:SecretPassword https://localhost:9200/_template/wazuh
curl -sk -u admin:SecretPassword https://localhost:9200/_cat/indices/wazuh-alerts-*?v
```

On a fresh deployment without enrolled agents, `wazuh-alerts-*` indices may still
be absent until the first alerts are generated. The template check above should
already return JSON containing `wazuh-alerts`.

## Network access restriction

By default, the official Wazuh single-node Docker Compose file publishes its service ports on the Docker host. With Docker port publishing, do not rely only on classic `ufw` rules: Docker manages its own forwarding rules, and traffic to published container ports can bypass the usual `INPUT` chain filtering.

Use the Docker `DOCKER-USER` chain to filter traffic before Docker accepts forwarded packets to published container ports. Replace every placeholder with the customer network plan before deployment:

```text
External interface:  <EXTERNAL_INTERFACE>
Admin subnet:        <ADMIN_SUBNET>
Agent subnet:        <AGENT_SUBNET>
API client subnet:   <API_CLIENT_SUBNET>
Syslog subnet:       <SYSLOG_SUBNET>
```

Find the default outbound interface on the VM before replacing `<EXTERNAL_INTERFACE>`:

```bash
ip route get 1.1.1.1 | awk '{for (i=1; i<=NF; i++) if ($i == "dev") print $(i+1)}'
```

Example baseline rules:

```bash
sudo iptables -I DOCKER-USER 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

sudo iptables -I DOCKER-USER 2 -i <EXTERNAL_INTERFACE> -p tcp --dport 443 -s <ADMIN_SUBNET> -j ACCEPT
sudo iptables -I DOCKER-USER 3 -i <EXTERNAL_INTERFACE> -p tcp --dport 1514 -s <AGENT_SUBNET> -j ACCEPT
sudo iptables -I DOCKER-USER 4 -i <EXTERNAL_INTERFACE> -p tcp --dport 1515 -s <AGENT_SUBNET> -j ACCEPT
sudo iptables -I DOCKER-USER 5 -i <EXTERNAL_INTERFACE> -p udp --dport 514 -s <SYSLOG_SUBNET> -j ACCEPT

sudo iptables -I DOCKER-USER 6 -i <EXTERNAL_INTERFACE> -p tcp --dport 55000 -s <API_CLIENT_SUBNET> -j ACCEPT
sudo iptables -I DOCKER-USER 7 -i <EXTERNAL_INTERFACE> -p tcp --dport 9200 -s <ADMIN_SUBNET> -j ACCEPT

sudo iptables -A DOCKER-USER -i <EXTERNAL_INTERFACE> -p tcp --dport 443 -j DROP
sudo iptables -A DOCKER-USER -i <EXTERNAL_INTERFACE> -p tcp --dport 1514 -j DROP
sudo iptables -A DOCKER-USER -i <EXTERNAL_INTERFACE> -p tcp --dport 1515 -j DROP
sudo iptables -A DOCKER-USER -i <EXTERNAL_INTERFACE> -p udp --dport 514 -j DROP
sudo iptables -A DOCKER-USER -i <EXTERNAL_INTERFACE> -p tcp --dport 55000 -j DROP
sudo iptables -A DOCKER-USER -i <EXTERNAL_INTERFACE> -p tcp --dport 9200 -j DROP
```

Port intent:

```text
443/tcp    Dashboard web access. Allow only administrators or trusted user networks.
1514/tcp   Wazuh agent event traffic. Allow only enrolled endpoint networks.
1515/tcp   Wazuh agent enrollment. Allow only endpoint networks during enrollment.
514/udp    Syslog ingestion. Allow only trusted syslog senders.
55000/tcp  Wazuh manager API. Avoid public exposure; allow only approved API clients or automation sources.
9200/tcp   Wazuh indexer API. Avoid public exposure; allow only admin or maintenance sources if needed.
```

If the indexer API is not required from outside the Docker host, do not add the `9200/tcp` allow rule. If the manager API is not required from outside the Docker host, do not add the `55000/tcp` allow rule.

The exact rules depend on the client environment:

- If agents come from several networks, add one allow rule per agent subnet for `1514/tcp` and `1515/tcp`.
- If API clients or automation systems come from several networks, add one allow rule per approved API client subnet for `55000/tcp`.
- If syslog sources use TCP instead of UDP, add an explicit `514/tcp` allow and drop pair.
- If the VM has IPv6 enabled and Docker publishes IPv6 ports, mirror the policy with `ip6tables`.
- Make these rules persistent with the distribution firewall tooling, for example `iptables-persistent` on Debian, after validating them on the test VM.

Do not apply the final `DROP` rules until the customer-approved dashboard, agent, API client, and syslog source networks are known. Applying the drops too early can block legitimate agents, API clients, or log senders.

Before exposing the VM outside an isolated lab, verify the effective policy:

```bash
sudo iptables -S DOCKER-USER
sudo docker compose -f /opt/wazuh/wazuh-docker/single-node/docker-compose.yml ps
```

Then test from allowed and denied source networks. The deployment should be considered incomplete until dashboard, agent, enrollment, syslog, API, and indexer exposure match the customer security requirements.

## Certificates

The Wazuh Docker stack requires certificates to secure communication between Wazuh components. This installer uses the official `wazuh-certs-generator` Docker image to generate Wazuh self-signed certificates for the selected stack.

Browsers will usually display a security warning when accessing the Wazuh dashboard with these self-signed certificates.

For any environment beyond a PoC, review the official Wazuh certificate documentation and use certificates issued by an internal or public certificate authority trusted by your organization and browsers. Do not treat the generated PoC certificates as production-ready material.

## Default credentials

```text
Username: admin
Password: SecretPassword
```

These are the default Wazuh Docker dashboard credentials documented by Wazuh for the initial login.

Default credentials are suitable only for an initial PoC/lab installation. Change the dashboard password and review all default Wazuh Docker credentials before connecting real endpoints or exposing the service to other users.

The Wazuh Docker stack also contains internal service credentials used by the Wazuh API, indexer, and dashboard integrations. Review the official Wazuh password change procedure instead of changing only the dashboard password manually.

Follow the official Wazuh documentation for password changes:

<https://documentation.wazuh.com/current/deployment-options/docker/index.html#changing-the-default-password-of-wazuh-users>

## Mini Wazuh configuration tutorial

After installation, wait until all containers are running and healthy:

```bash
sudo docker compose -f /opt/wazuh/wazuh-docker/single-node/docker-compose.yml ps
```

The dashboard can take a few minutes to become available while the Wazuh indexer starts. During startup, dashboard logs can show temporary connection errors to the indexer.

To enroll an endpoint:

1. Open the Wazuh dashboard.
2. Log in with the initial admin credentials.
3. Go to `Agents`.
4. Click `Deploy new agent`.
5. Select the endpoint operating system.
6. Enter the Wazuh manager IP address or DNS name.
7. Copy the generated installation command.
8. Run it on the endpoint with administrator or root privileges.
9. Start or restart the Wazuh agent on the endpoint.
10. Confirm that the agent appears as active in the dashboard.

Create groups when endpoints need different monitoring policies. For example, use separate groups for Linux servers, Windows workstations, domain controllers, DMZ systems, or critical assets.

After agents are enrolled, review the dashboard modules for security events, vulnerability detection, file integrity monitoring, configuration assessment, and MITRE ATT&CK mapping.

### Optional local agent FIM realtime

By default, the installer does not modify a Wazuh agent installed on the Docker
host. This avoids changing client endpoint monitoring policy unexpectedly.

For lab deployments where the Docker host also runs a local Wazuh agent and you
want File Integrity Monitoring events to appear immediately for common system
paths, answer yes when the installer asks:

```text
Enable local File Integrity Monitoring (FIM) realtime on this host? [y/N]:
```

For non-interactive deployments, enable the optional realtime FIM configuration
explicitly:

```bash
sudo EASY_WAZUH_ENABLE_LOCAL_AGENT_FIM_REALTIME=yes ./easy-wazuh-bootstrap.sh
```

When enabled, the installer backs up `/var/ossec/etc/ossec.conf`, changes the
local agent syscheck entry for `/etc,/usr/bin,/usr/sbin` to realtime mode, and
restarts the local `wazuh-agent` service if it exists.

Without this option, FIM can still work in scheduled mode according to the
agent's own `frequency` setting. Scheduled mode can leave the dashboard
`FIM: Recent events` panel empty until a scan detects changes.

## Disclaimer

This script is provided as a proposal/example and was developed as part of a proof of concept (PoC). It has not been tested in a production environment. Before any use or deployment in production, users must take all necessary precautions, review and understand the code, adapt it to their own context, and thoroughly test it.

## License

This project is licensed under the GNU General Public License v3.0 (`GPL-3.0-only`).

You can use, copy, share, and modify this project under the terms of the GPL.

Full license text: <https://www.gnu.org/licenses/gpl-3.0.html>
