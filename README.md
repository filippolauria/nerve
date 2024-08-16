
# Network Exploration, Reconnaissance, Vulnerability, Integrated Unit for continuous Monitoring

![NERVIUM](../../blob/master/static/screenshots/2.png?raw=true)

  

# Table of Contents

* [About NERVIUM](#about-nervium)

* [Features](#features)

* [Prerequisites](#prerequisites)

* [Installation](#installation)

* [Deployment recommendations](#deployment-recommendations)

* [Standalone deployment](#standalone-deployment)

* [Multi-Node deployment](#multi-node-deployment)

* [Upgrade](#upgrade)

* [Security](#security)

* [Usage](#usage)

* [License](#license)

* [Mentions](#mentions)

* [Screenshots](#screenshots)


# About NERVIUM

NERVIUM is a vulnerability scanner designed to identify low-hanging fruit vulnerabilities in specific application configurations, network services, and unpatched services.

Some examples of NERVIUM's detection capabilities include:
* **Interesting Panels** (e.g., Solr, Django, PHPMyAdmin)
* **Subdomain Takeovers**
* **Open Repositories**
* **Information Disclosures**
* **Abandoned / Default Web Pages**
* **Misconfigurations** in services (e.g., Nginx, Apache, IIS)
* **SSH Servers**
* **Open Databases**
* **Open Caches**
* **Directory Indexing**
* **Best Practices**

NERVIUM is not a replacement for tools like Qualys, Nessus, or OpenVAS. It does not perform authenticated scans and operates solely in black-box mode.

# Features

NERVIUM offers the following features:

* **Dashboard** (with a login interface)
* **REST API** (for scheduling assessments, obtaining results, etc.)
* **Notifications**
  * Slack
  * Email
  * Webhook
* **Reports**
  * TXT
  * CSV
  * HTML
  * XML
* **Customizable Scans**
  * Configurable intrusiveness levels
  * Scan depth
  * Exclusions
  * DNS / IP Based
  * Thread control
  * Custom ports
* **Network Topology Graphs**

NERVIUM's Web-GUI is designed for ease of use.


  

# Prerequisites

NERVIUM will automatically install all the prerequisites if you choose the Server installation by using the `install/setup.sh` script.

Keep in mind that NERVIUM requires root access for the initial setup on bare metal (including package installation).

### Services and Packages Required for NERVIUM to Run:

* **Web Server** (Flask)
* **Redis Server** (binds locally)
* **Nmap Package** (binary and Python Nmap library)
* **Inbound Access on HTTP/S Port** (configurable in `config.py`)

The installation script takes care of everything for you. However, if you prefer to install it manually, please ensure that these requirements are met.


# Installation

## Deployment recommendations

To achieve optimal results with NERVIUM, we recommend the following deployment strategy and best practices:

- **Deployment Strategy**: Deploy NERVIUM across multiple regions (e.g., in different countries) and enable continuous mode to effectively identify short-lived vulnerabilities in dynamic environments and cloud setups. This approach provides a more comprehensive assessment and helps catch vulnerabilities that might otherwise be missed.

- **IP Whitelisting**: We typically recommend **not** whitelisting the IP addresses from which NERVIUM initiates scans. This approach ensures a more realistic evaluation from an attacker’s perspective.

- **System Requirements**:
  - **Operating System**: Debian (latest stable release preferred)
  - **Memory**: At least 8GB of RAM on the node where Redis is installed

  These recommendations help ensure that Redis operates efficiently and NERVIUM performs optimally.

- **Database Usage**: To keep NERVIUM lightweight, it relies solely on Redis and does not require a traditional database.

- **Long-Term Storage**: For long-term storage of vulnerabilities, we recommend using the Webhook feature. At the end of each scan cycle, NERVIUM can dispatch a JSON payload to a specified endpoint, allowing you to store and analyze the data in your preferred database.

By following these recommendations, you can ensure that NERVIUM operates effectively and integrates seamlessly into your infrastructure.


### Recommended steps for optimal results:

1. Deploy NERVIUM on one or more servers.
2. Create a script to fetch your cloud services (e.g., AWS Route53 for DNS, AWS EC2 for instance IPs, AWS RDS for database IPs) and a static list of IP addresses if you have assets in a datacenter.
3. Use the NERVIUM API (`POST /api/scan/submit`) to schedule scans with the assets gathered in step 2.
4. Fetch the results programmatically and take action (e.g., SOAR, JIRA, SIEM).
5. Implement your own logic (e.g., exclude certain alerts, add to a database).
   

# Standalone deployment

**To perform the following steps, please ensure that you are running the terminal as the root user or with root privileges.**

### Clone the repository /opt/nervium

```bash
git clone https://github.com/filippolauria/nervium.git /opt/nervium
```

### Navigate to /opt/nervium

```bash
cd /opt/nervium
```

### Run Installer

```bash
source install/setup.sh
```

### Check NERVIUM is running

```bash
systemctl status nervium.service
```
**Note**: at the end of the procedure, the installation script will provide you with the information to login to your NERVIUM instance using your favourite browser.

# Multi-Node Deployment

If you want to install NERVIUM in a multi-node deployment, you can follow the normal bare metal installation process. Afterward:

1. Modify the `config.py` file on each node.
   
2. Change the Redis server address (`RDS_HOST`) to point to a central Redis server that all NERVIUM instances will report to.

3. Run `systemctl restart nervium.service` to reload the configuration.

4. Run `apt remove redis` since you will no longer need each instance to report to itself.

Don't forget to allow port 3769 inbound on the Redis instance, so that the NERVIUM instances can communicate with it.


# Upgrade

If you want to upgrade your platform, the fastest way is to simply git clone and overwrite all the files while keeping key files such as configurations.

* Make a copy of `config.py` if you wish to save your configurations

* Remove `/opt/nervium` and git clone it again.

* Move `config.py` file back into `/opt/nervium`

* Restart the service using `systemctl restart nervium.service`.

You could set up a cron task to auto-upgrade NERVIUM. There's an API endpoint to check whether you have the latest version or not that you could use for this purpose: `GET /api/update/platform`

# Security

There are a few security mechanisms implemented into NERVIUM you need to be aware of. 

* Content Security Policy - A response header which controls where resource scan be loaded from.

* Other Security Policies - These Response headers are enabled: Content-Type Options, X-XSS-Protection, X-Frame-Options, Referer-Policy

* Brute Force Protection - A user will get locked if more than 5 incorrect login attempts are made.

* Cookie Protection - Cookie security flags are used, such as SameSite, HttpOnly, etc.

If you identify a security vulnerability, please submit a bug to us on [GitHub](../../issues).

We recommend to take the following steps before and after installation

1. Set a strong password (a password will be set for you if you use the bare metal installation)

2. Protect the inbound access to the panel (Add your management IP addresses to the allow list of the local firewall)

3. Add HTTPS (you can either patch Flask directly, or use a reverse proxy like nginx)

4. Keep the instance patched


# Usage

To learn about NERVIUM (GUI, API, etc.) we advise you to check out the documentation available to you via the platform.

Once you deploy it, authenticate and on the left sidebar you will find a documentation link for API and GUI usage.

  

## GUI Documentation

![NERVIUM](../../blob/master/static/screenshots/10.png?raw=true)

  

## API Documentation

![NERVIUM](../../blob/master/static/screenshots/11.png?raw=true)

  


# License

NERVIUM is distributed under the MIT License. See LICENSE for more information.

**Note:** NERVIUM is a fork of [NERVE](https://github.com/PaytmLabs/nerve).
  

# Screenshots

## Login Screen

![NERVIUM](../../blob/master/static/screenshots/1.png?raw=true)

## Dashboard Screen

![NERVIUM](../../blob/master/static/screenshots/2.png?raw=true)

## Assessment Configuration

![NERVIUM](../../blob/master/static/screenshots/3.png?raw=true)

## API Documentation

![NERVIUM](../../blob/master/static/screenshots/4.png?raw=true)

## Reporting

![NERVIUM](../../blob/master/static/screenshots/5.png?raw=true)

## Network Map

![NERVIUM](../../blob/master/static/screenshots/6.png?raw=true)

## Vulnerability page

![NERVIUM](../../blob/master/static/screenshots/7.png?raw=true)

## Log Console

![NERVIUM](../../blob/master/static/screenshots/8.png?raw=true)

## HTML Report

![NERVIUM](../../blob/master/static/screenshots/9.png?raw=true)
