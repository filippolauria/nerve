#!/bin/bash

# Nerve installation script.

_green='\033[0;32m'
_red='\033[0;31m'
_blue='\033[0;34m'
_nc='\033[0m' # No Color

# path of NERVE' systemd file
systemd_service="/lib/systemd/system/nerve.service"

installation_dir="/opt/nerve"

# default port
port=8080

# current working directory
cwd="$(pwd)"

password=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 12)
username="admin_"$(cat /dev/urandom | tr -dc '0-9' | head -c 4)

is_fresh_installation() {
  # 0 means true
  if [ -f $systemd_service ]; then return 1; else return 0; fi
}

is_app_running() {
  systemctl is-active --quiet nerve
  if [ $? != 0 ]; then return 1; else return 0; fi
}

setup_port() {
  # if NERVE's config.py exists...
  if [ -f "config.py" ]; then
    # ... we get the old TCP port from it...
    port=$(grep WEB_PORT config.py | awk -F' = ' '{print $2}')
  fi

  # ... otherwise we use the default 8080/TCP. 
}

print_red() {
  echo -e "${_red}$1${_nc}"
}

print_blue() {
  echo -e "${_blue}$1${_nc}"
}

print_green() {
  echo -e "${_green}$1${_nc}"
}

ensure_debian() {
  # operating system
  os=$(grep '^ID=' /etc/*-release | cut -d'=' -f2)

  if [ "${os}" != "debian" ]; then
    return 1
  fi
}

ensure_root() {
  if [ "$(id -u)" -ne 0 ]; then
    return 1
  fi
}

ensure_opt_dir() {
  if [ "${cwd}" != "${installation_dir}" ]; then
    return 1
  fi
}

ensure_requirements() {
  if [ ! -f "requirements.txt" ]; then
    return 1
  fi  
}

# this function installs required packages
install_packages() {
  apt -y -o 'Acquire::ForceIPv4=true' update && \
  
  apt --no-install-recommends -o 'Acquire::ForceIPv4=true' -y install \
    libpq-dev libjpeg-dev libffi-dev libfreetype-dev libfreetype6 libfreetype6-dev \
    gcc redis wget nmap && \

  apt --no-install-recommends -o 'Acquire::ForceIPv4=true' -y install python3 python3-pip python3-dev virtualenv

  if [ $? != 0 ]; then
    return 1
  fi
}

check_ipv4_connectivity() {
  if ! ping -4 -c 1 -W 3 ipv4.google.com &> /dev/null; then
    return 1
  fi
}

# this function configures SELinux
configure_selinux() {
  if [ ! -f "/sbin/setenforce" ]; then
    return 0
  fi

  setenforce 0
  if [ $? != 0 ]; then
    return 1
  fi
    
  local selinux_conf_file="/etc/sysconfig/selinux"
  if [ ! -f "${selinux_conf_file}" ]; then
    return 0
  fi
  
  if ! grep -q enforcing "${selinux_conf_file}"; then
    return 0
  fi
    
  sed -i "s/enforcing/permissive/g" "${selinux_conf_file}" &> /dev/null
  if [ $? != 0 ]; then
    return 1
  fi
}

retrieve_credentials_from_systemd_unit() {
  # if NERVE' systemd file exists...
  if ! is_fresh_installation; then
    # ... we get the old username/password pair...
    password=$(grep "Environment=password=" "${systemd_service}")
    username=$(grep "Environment=username=" "${systemd_service}")
    password=${password#"Environment=password="}
    username=${username#"Environment=username="}
  fi

  # ... otherwise we generate new random access credentials.
}

shutdown_running_instance() {
  if is_fresh_installation; then
    return 0
  fi

  if ! is_app_running; then
    return 0
  fi

  systemctl stop nerve.service
  if [ $? != 0 ]; then
    return 1
  fi

  return 0
}

enable_and_start_redis() {
  systemctl enable redis-server.service && \
  systemctl start redis-server.service
  if [ $? != 0 ]; then
    return 1
  fi
}

install_python_env() {
  # we create a new python3 virtual environment
  local env_dir="${installation_dir}/env"
  rm -rf "${env_dir}" && \
  mkdir "${env_dir}" && \
  chmod 640 "${env_dir}" && \
  virtualenv -q "${env_dir}"

  if [ $? != 0 ]; then
    return 1
  fi
}

setup_python_env() {
  # we install python3 dependencies
  . "${installation_dir}/env/bin/activate"
  "${installation_dir}/env/bin/pip3" install -r requirements.txt
  
  if [ $? != 0 ]; then
    return 1
  fi
}

setup_systemd_unit() {
  # we create a systemd unit
  
  cat <<EOF > "$systemd_service"
[Unit]
Description=NERVE
After=network.target redis-server.service

[Service]
Type=simple
WorkingDirectory=${installation_dir}
Environment=username=${username}
Environment=password=${password}
ExecStart=/bin/bash -c 'cd ${installation_dir}/ && ${installation_dir}/env/bin/python3 ${installation_dir}/main.py'

[Install]
WantedBy=multi-user.target
EOF
  if [ $? != 0 ]; then
    return 1
  fi

  chown root:root "${systemd_service}" && chmod 640 "${systemd_service}"
  if [ $? != 0 ]; then
    return 1
  fi
}

enable_and_start_app() {
  # we enable and start NERVE
  systemctl daemon-reload && \
  systemctl enable nerve.service && \
  systemctl start nerve.service
}

# only debian is supported
if ! ensure_debian; then
  print_red "[!] Only debian OS is supported."
  return 1
fi

# we want that this script is being executed as root.
if ! ensure_root; then
  print_red "[!] This script needs to be run as root."
  return 1
fi

# we want that this script is executed from the `installation_directory` folder.
if ! ensure_opt_dir; then
  print_red "[!] This script must be sourced from within the folder ${installation_dir}"
  return 1 
fi

# we make sure that requirements.txt is present in the cwd folder.
if ! ensure_requirements; then
  print_red "[!] requirements.txt is missing. Did you unpack the files into ${installation_dir}?"
  return 1
fi

# # we make sure that a working Internet connection is present.
if ! check_ipv4_connectivity; then
  print_red "[!] You must have a working internet connection to download the dependencies."
  return 1
fi

# # setup port
setup_port

if ! shutdown_running_instance; then
  print_blue "[!] Failed to shutdown running instance."
fi

# if this is not a fresh install we retrieve old creds
retrieve_credentials_from_systemd_unit

print_blue "[+] Installing packages..."
if ! install_packages; then
  print_red "[!] Error while installing packages."
  return 1
fi

# # start redis
print_blue "[+] Starting Redis..."
if ! enable_and_start_redis; then
  print_red "[!] Failed to enable or starting redis."
  return 1
fi

print_blue "[+] Creating python3 virtual environment..."
if ! install_python_env; then
  print_red "[!] Failed to create python3 virtual environment."
  return 1
fi

print_blue "[+] Setting up python3 virtual environment..."
if ! setup_python_env; then
  print_red "[!] Failed to setup virtual environment."
  return 1
fi

print_blue "[+] Setting up systemd service..."
if ! setup_systemd_unit; then
  print_red "[!] Failed to set up systemd service."
  return 1
fi

# we check and setup SELinux (if present)
if ! configure_selinux; then
  print_red "[!] Failed to make SELinux permissive."
fi

print_blue "[+] Starting service... "
enable_and_start_app

if ! is_app_running; then
  print_red "[!] Something went wrong and the service could not be started."
fi

print_green "[+] Setup Complete!"

echo -e "[+] You may access NERVE using the following URL: ${_blue}http://your_ip_here${_nc}:${_green}${port}${_nc}."

cat <<EOL
[+] Credentials:
    - You must have valid credentials to access NERVE.

EOL
  
if is_fresh_installation; then
  cat <<EOL
    - Since this is a fresh installation,
      some random credentials have been generated.
EOL
else
  cat <<EOL
    - Since this is not a fresh installation,
      your old credentials have been kept.
EOL
fi

echo -e "    - NERVE stores credentials in the file ${_blue}${systemd_service}${_nc},"

cat <<EOL
      which is owned and readable/writable by root only.
    - You can change your credentials by editing that file.
      Once done, remember to reload and restart NERVE:
EOL

echo -e "        ${_blue}systemctl daemon-reload && systemctl restart nerve${_nc}"
