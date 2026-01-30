## Adding lousy pseudo HA features for the Hashicorp Vault ##
## This guide is built on the add_tpm_to_proxmox.md ##

The issue:  
Vault is upon pod restarts sealed by default due to security keeping.
This highly affects company workflows and running an air-gapped cloud-in-a-box
on a singlenode cluster yield some peculiar design choices.

The approach:  
Automate the unseal process so CIAB can go fully up and healthy
after system reboots or restarts of the Vault pod.
Without pushing vulnerable credentials into Kubernetes.

The general solution:  
A KMS solution is often sought for for this that
manages the unseal process, it's also possible to leverage
Hashicorp Vault's own transit engine unseal.

The CIAB solution:  
Instead of running its own provided Vault cluster
we will set up a Vault system server running on the kubeadm host
to ensure the autounseal of the Vault secondary -
which in turn will portion out secrets to all the pods.

## The flow ##

Vault Transit Auto-Unseal using TLS Certificate Auth
High-level flow (what will happen)

External (host) Vault trusts a client CA

Kubernetes Vault presents a client certificate

External Vault authenticates Kubernetes Vault via TLS cert auth

Kubernetes Vault uses the resulting token only to:

encrypt/decrypt the transit unseal key

No static tokens, no secrets in Kubernetes

## Preset ##
### Install Vault as a systemd service running on host - Use the TPM functionality to ensure it unsealed without secure key leakage ###

```
wget -O - https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(grep -oP '(?<=UBUNTU_CODENAME=).*' /etc/os-release || lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list

administrator@ciab:~$ sudo apt-get update
Hit:1 http://se.archive.ubuntu.com/ubuntu noble InRelease
Get:2 http://se.archive.ubuntu.com/ubuntu noble-updates InRelease [126 kB]                                                                                                        
Get:3 https://nvidia.github.io/libnvidia-container/stable/deb/amd64  InRelease [1477 B]                                                                                                      
Get:4 http://se.archive.ubuntu.com/ubuntu noble-backports InRelease [126 kB]                                                                                                                 
Hit:5 http://security.ubuntu.com/ubuntu noble-security InRelease                                                                                            
Get:7 https://apt.releases.hashicorp.com noble InRelease [12.9 kB]                        
Get:8 http://se.archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages [1700 kB]               
Get:9 http://se.archive.ubuntu.com/ubuntu noble-updates/universe amd64 Packages [1519 kB]                                    
Get:10 http://se.archive.ubuntu.com/ubuntu noble-updates/universe Translation-en [310 kB]                                    
Hit:6 https://prod-cdn.packages.k8s.io/repositories/isv:/kubernetes:/core:/stable:/v1.35/deb  InRelease    
Get:12 https://apt.releases.hashicorp.com noble/main amd64 Packages [218 kB]                        
Hit:11 https://packages.buildkite.com/helm-linux/helm-debian/any any InRelease                 
Fetched 4014 kB in 2s (2346 kB/s)
Reading package lists... Done
administrator@ciab:~$ sudo apt-get install vault
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following packages were automatically installed and are no longer required:
  conntrack libtcl8.6 tcl tcl-dev tcl-trf tcl8.6 tcl8.6-dev tcllib
Use 'sudo apt autoremove' to remove them.
The following NEW packages will be installed:
  vault
0 upgraded, 1 newly installed, 0 to remove and 21 not upgraded.
Need to get 170 MB of archives.
After this operation, 513 MB of additional disk space will be used.
Get:1 https://apt.releases.hashicorp.com noble/main amd64 vault amd64 1.21.2-1 [170 MB]
Fetched 170 MB in 2s (80.9 MB/s)
Selecting previously unselected package vault.
(Reading database ... 158820 files and directories currently installed.)
Preparing to unpack .../vault_1.21.2-1_amd64.deb ...
Unpacking vault (1.21.2-1) ...
Setting up vault (1.21.2-1) ...
Generating Vault TLS key and self-signed certificate...

Vault TLS key and self-signed certificate have been generated in '/opt/vault/tls'.
```

### Generate the proper vault-host keys to use for the TLS auth ###

```
administrator@ciab:/opt/vault$ sudo su
[sudo] password for administrator: 
root@ciab:/opt/vault# cd tls
root@ciab:/opt/vault/tls# ls
tls.crt  tls.key
root@ciab:/opt/vault/tls# mkdir tls_backup
root@ciab:/opt/vault/tls# systemctl status vault
○ vault.service - "HashiCorp Vault - A tool for managing secrets"
     Loaded: loaded (/usr/lib/systemd/system/vault.service; disabled; preset: enabled)
     Active: inactive (dead)
       Docs: https://developer.hashicorp.com/vault/docs
root@ciab:/opt/vault/tls# ls
tls_backup  tls.crt  tls.key
root@ciab:/opt/vault/tls# mv tls.crt tls.key tls_backup
root@ciab:/opt/vault/tls# ls
tls_backup
root@ciab:/opt/vault/tls# openssl genrsa -out /opt/vault/tls/vault-host.key 4096
root@ciab:/opt/vault/tls# ls
tls_backup  vault-host.key

root@ciab:/opt/vault/tls# cat vault-openssl.conf 
# vault-openssl.cnf
[ req ]
default_bits       = 4096
prompt             = no
default_md         = sha256
distinguished_name = dn
req_extensions     = req_ext

[ dn ]
CN = vault-host.enclave.local

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = vault-host.enclave.local
DNS.2 = vault


root@ciab:/opt/vault/tls# openssl req -new -key vault-host.key -out vault-host.csr -config vault-openssl.conf

root@ciab:/opt/vault/tls# openssl x509 -req \
  -in vault-host.csr \
  -CA /adminroot/pki/ca.crt \
  -CAkey /adminroot/pki/ca.key \
  -CAcreateserial \
  -out vault-host.crt \
  -days 365 \
  -extensions req_ext \
  -extfile vault-openssl.conf
Certificate request self-signature ok
subject=CN = vault-host.enclave.local
root@ciab:/opt/vault/tls# ls
tls_backup  vault-host.crt  vault-host.csr  vault-host.key  vault-openssl.conf
root@ciab:/opt/vault/tls# 
```

### Verify the vault.hcl ###

```
administrator@ciab:~$ sudo cat /etc/vault.d/vault.hcl
# Copyright IBM Corp. 2016, 2025
# SPDX-License-Identifier: BUSL-1.1

# Full configuration options can be found at https://developer.hashicorp.com/vault/docs/configuration

ui = false

#mlock = true
disable_mlock = true

storage "file" {
  path = "/opt/vault/data"
}

#storage "consul" {
#  address = "127.0.0.1:8500"
#  path    = "vault"
#}

# HTTP listener
#listener "tcp" {
#  address = "127.0.0.1:8200"
#  tls_disable = 1
#}

# HTTPS listener
listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "/opt/vault/tls/vault-host.crt"
  tls_key_file  = "/opt/vault/tls/vault-host.key"
  tls_client_ca_file = "/opt/vault/tls/ca.crt"

  tls_require_and_verify_client_cert = true
}

# Enterprise license_path
# This will be required for enterprise as of v1.8
#license_path = "/etc/vault.d/vault.hclic"

# Example AWS KMS auto unseal
#seal "awskms" {
#  region = "us-east-1"
#  kms_key_id = "REPLACE-ME"
#}

# Example HSM auto unseal
#seal "pkcs11" {
#  lib            = "/usr/vault/lib/libCryptoki2_64.so"
#  slot           = "0"
#  pin            = "AAAA-BBBB-CCCC-DDDD"
#  key_label      = "vault-hsm-key"
#  hmac_key_label = "vault-hsm-hmac-key"
#}

```

### Fix permissions and start the server ###

```
sudo chown root:vault /opt/vault/tls
sudo chmod 770 /opt/vault/tls

sudo chown vault:vault /opt/vault/tls/vault-host.key
sudo chmod 600 /opt/vault/tls/vault-host.key

sudo chown vault:vault /opt/vault/tls/vault-host.crt
sudo chmod 644 /opt/vault/tls/vault-host.crt

sudo chown vault:vault /opt/vault/tls/ca.crt
sudo chmod 644 /opt/vault/tls/ca.crt

sudo systemctl start vault
```

### Ensure the DNS resolve of local ###

```
administrator@ciab:~$ cat /etc/hosts
127.0.0.1 localhost
127.0.1.1 ciab

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

192.168.1.106 harbor.local nextcloud.local awesomecloud.local
127.0.0.1 vault-host.enclave.local
```

### Fix the environment variables ###

```
administrator@ciab:~$ sudo mkdir /home/vault
administrator@ciab:~$ sudo chown vault:vault /home/vault
administrator@ciab:~$ sudo chmod 700 /home/vault
administrator@ciab:~$ grep vault /etc/passwd
vault:x:999:988::/home/vault:/bin/false
administrator@ciab:~$ sudo usermod -d /home/vault -s /bin/bash vault
administrator@ciab:~$ 
```

Create .bashrc if you want per-user env vars:
```
sudo -u vault vi /home/vault/.bashrc
```

Add:

```
export VAULT_ADDR="https://vault-host.enclave.local:8200"
export VAULT_CACERT="/opt/vault/tls/ca.crt"
export VAULT_CLIENT_CERT=/opt/vault/tls/vault-client.crt
export VAULT_CLIENT_KEY=/opt/vault/tls/vault-client.key
```

Create a .bash_profile:
```
sudo -u vault vi /home/vault/.bash_profile
```

Add:

```
if [ -f ~/.bashrc ]; then
  . ~/.bashrc
fi
```

```
sudo usermod -aG tss vault
```

## Generate client keys to use ##

```
# generate client key
openssl genrsa -out /opt/vault/tls/vault-client.key 4096

# generate client CSR
openssl req -new -key /opt/vault/tls/vault-client.key -out /opt/vault/tls/vault-client.csr -subj "/CN=vault-client"

# sign with CA
openssl x509 -req -in /opt/vault/tls/vault-client.csr \
  -CA /opt/vault/tls/ca.crt \
  -CAkey /adminroot/pki/ca.key \
  -CAcreateserial \
  -out /opt/vault/tls/vault-client.crt \
  -days 365
  
sudo chown vault:vault /opt/vault/tls/vault-client.key
sudo chmod 600 /opt/vault/tls/vault-client.key

sudo chown vault:vault /opt/vault/tls/vault-client.crt
sudo chmod 644 /opt/vault/tls/vault-client.crt
  
```  

## Initialise the Vault server ##

```
sudo -u vault -i
vault operator init -key-shares=5 -key-threshold=3
```

## Implement the TPM unseal for Vault Host ##

```
2️⃣ Create a TPM-sealed unseal blob

sudo su

Combine unseal keys
cat <<EOF > /root/vault-unseal.txt
key1
key2
key3
EOF

(only threshold number needed)

Seal into TPM (PCR-bound)

tpm2_clear

tpm2_createprimary -C e -c primary.ctx
  
tpm2_create \
  -C primary.ctx \
  -G aes128cfb \
  -u unseal.pub \
  -r unseal.priv \
  -a "sign|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth"
  
tpm2_load -C primary.ctx -u unseal.pub -r unseal.priv -c unseal.ctx

tpm2_evictcontrol -C o -c unseal.ctx 0x81010001

mkdir /opt/vault/unseal

sudo chown root:vault /opt/vault/unseal
sudo chmod 750 /opt/vault/unseal

head -c 16 /dev/urandom > /opt/vault/unseal/iv.bin

sudo chown vault:vault /opt/vault/unseal/iv.bin
sudo chmod 600 /opt/vault/unseal/iv.bin

sudo chown vault:vault /opt/vault/unseal/unseal.blob
sudo chmod 600 /opt/vault/unseal/unseal.blob

Encrypt the unseal blob with TPM
tpm2_encryptdecrypt \
  -c 0x81010001 \
  -G cfb \
  -t /opt/vault/unseal/iv.bin \
  -o /opt/vault/unseal/unseal.blob \
  /root/vault-unseal.txt


Then securely delete:

shred -u /root/vault-unseal.txt
```

## Prepare the unseal systemd service ##

/etc/systemd/system/vault-auto-unseal.service
```
[Unit]
Description=TPM-backed Vault Auto Unseal
After=dev-tpmrm0.device vault.service
Requires=vault.service

[Service]
Type=oneshot
User=vault
Group=vault

WorkingDirectory=/home/vault
RuntimeDirectory=vault
RuntimeDirectoryMode=0700
ExecStart=/home/vault/vault-tpm-unseal.sh

# Explicit environment (systemd does NOT read .bashrc)
Environment=TPM2TOOLS_TCTI=device:/dev/tpmrm0
Environment=VAULT_ADDR=https://vault-host.enclave.local:8200
Environment=VAULT_CACERT=/opt/vault/tls/ca.crt
Environment=VAULT_CLIENT_CERT=/opt/vault/tls/vault-client.crt
Environment=VAULT_CLIENT_KEY=/opt/vault/tls/vault-client.key

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes

# Explicit filesystem access
ReadWritePaths=/run
ReadOnlyPaths=/opt/vault

# TPM device access
DeviceAllow=/dev/tpmrm0 rw

[Install]
WantedBy=multi-user.target
```


## Prepare the unseal script ## 

```
sudo mkdir /run/vault
sudo chown vault:vault /run/vault
sudo chmod 700 /run/vault
sudo -u vault -i
vi vault-tpm-unseal.sh
```

vault-tpm-unseal.sh
```
#!/bin/bash
set -euo pipefail

export TPM2TOOLS_TCTI=device:/dev/tpmrm0

BLOB="/opt/vault/unseal/unseal.blob"
IV="/opt/vault/unseal/iv.bin"
HANDLE="0x81010001"

# If Vault is already unsealed, exit cleanly
if vault status -format=json 2>/dev/null | grep -q '"sealed":false'; then
  exit 0
fi

TMP=$(mktemp /run/vault/vault-unseal.XXXXXX)

tpm2_encryptdecrypt \
  -d \
  -c "$HANDLE" \
  -G cfb \
  -t "$IV" \
  -o "$TMP" \
  "$BLOB"

# Unseal using each line (supports multi-key threshold)
while IFS= read -r key; do
  [ -z "$key" ] && continue
  vault operator unseal "$key"
done < "$TMP"

shred -u "$TMP"
```

Fix permissions
```
chmod 700 vault-tpm-unseal.sh
```

## Finalize the Vault Host setup ##

```
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable vault-auto-unseal
sudo systemctl start vault-auto-unseal.service
```

## Connect the Vault Host bootstrapper to the
## vault kubernetes pod via transit ##

### Step one ###

Generate a cert-manager issued TLS:
```
administrator@ciab:~/Kubernetes/Pods/HashVault$ cat 01-vault-transit-certificate.yaml 
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: vault-transit-tls
  namespace: hashvault
spec:
  secretName: vault-transit-tls
  duration: 2160h
  renewBefore: 360h
  dnsNames:
    - vault-k8s-transit
  issuerRef:
    name: osism-ca
    kind: ClusterIssuer
    
kubectl apply -f 01-vault-transit-certificate.yaml    
```   

```
kubectl get secret vault-transit-tls -n hashvault -o jsonpath='{.data.tls\.crt}' | base64 -d > vault-k8s.crt
sudo cp -Rvf vault-k8s.crt /opt/vault/tls/vault-k8s.crt
sudo chown vault:vault /opt/vault/tls/vault-k8s.crt
sudo chmod 644 /opt/vault/tls/vault-k8s.crt
```

Fix the TLS auth path for the Kubernetes Vault client,
on the Vault Host:

```
vault auth enable cert

vault write auth/cert/certs/k8s-vault \
  display_name="k8s-vault" \
  policies="k8s-vault-transit" \
  certificate=@/opt/vault/tls/vault-k8s.crt \
  allowed_dns_sans="vault-k8s-transit" \
  ttl=24h
```

### Step two - Enable transit ###

Enable transit:

```
vault secrets enable transit
```

Create unseal key:

```
vault write -f transit/keys/k8s-unseal
```

Policy:

```
# k8s-vault-transit.hcl
path "transit/keys/k8s-unseal" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Allow the user to encrypt and decrypt data using the autounseal key

path "transit/encrypt/k8s-unseal" {
  capabilities = ["create", "update"]
}

path "transit/decrypt/k8s-unseal" {
  capabilities = ["create", "update"]
}

# Allow the user to read the transit secrets engine configuration
path "transit/*" {
  capabilities = ["read", "list"]
}

# Allow the user to list all keys under the transit secrets engine
path "transit/keys/*" {
  capabilities = ["list"]
}
```

Apply it and generate the policy token:

```
vault policy write k8s-vault-transit k8s-vault-transit.hcl
vault token create -policy=k8s-vault-transit
```

### Update the Kubernetes Vault YAML ###

Add to 03-vault-config-configmap.yaml
```
seal "transit" {
  address         = "https://vault-host.enclave.local:8200"
  key_name        = "k8s-unseal"
  mount_path      = "transit/"
  tls_ca_cert     = "/vault/transit-tls/ca.crt"
  tls_client_cert = "/vault/transit-tls/tls.crt"
  tls_client_key  = "/vault/transit-tls/tls.key"
  token = "the-hvs-token-from-above-here"
}

```

Add to 07-vault-statefulset.yaml
```
env:
- name: VAULT_CACERT
  value: "/vault/transit-tls/ca.crt"

- name: VAULT_CLIENT_CERT
  value: "/vault/transit-tls/tls.crt"

- name: VAULT_CLIENT_KEY
  value: "/vault/transit-tls/tls.key"
  
...

volumeMounts:
  - name: vault-transit-tls
    mountPath: /vault/transit-tls
    readOnly: true
    
volumes:
  - name: vault-transit-tls
    secret:
      secretName: vault-transit-tls
      defaultMode: 0400
      
hostAliases:
  - ip: "192.168.1.106"
    hostnames:
      - "vault-host.enclave.local"
           
```     
```
kubectl apply -f 03-vault-config-configmap.yaml
kubectl apply -f 07-vault-statefulset.yaml
kubectl delete pod vault-0 -n hashvault
```

### Final step - Migrate from Shamir to Transit ###

Exec into the pod running
```
kubectl exec -it vault-0 -n hashvault -- sh
```

Do the migrate command by supplying your unseal keys:
```
vault operator unseal -migrate <unseal-key-one>
vault operator unseal -migrate <unseal-key-two>
vault operator unseal -migrate <unseal-key-three>
```

### Maintenance ###
To make this self sufficient a cronjob is needed under administrator
to stat the /opt/vault/tls/vault-k8s.crt
and diff it against the tls.crt that cert-manager rotates.

First ensure the permissions:

```
sudo usermod -aG vault administrator
sudo chown root:vault /opt/vault/tls
sudo chmod 770 /opt/vault/tls
sudo chmod 644 /opt/vault/tls/vault-k8s.crt
```

Create the cronjob script:

```
administrator@ciab:~/Kubernetes/CronJobs/CertRotations$ pwd
/home/administrator/Kubernetes/CronJobs/CertRotations
administrator@ciab:~/Kubernetes/CronJobs/CertRotations$ cat rotate-vault-k8s-crt.sh
#!/bin/bash
set -euo pipefail

# -------------------------------
# Configuration
# -------------------------------
NAMESPACE="hashvault"
SECRET="vault-transit-tls"
DEST="/opt/vault/tls/vault-k8s.crt"
USER="vault"
GROUP="vault"
VAULT_SERVICE="vault"

# Full paths for cron environment
KUBECTL="/usr/bin/kubectl"
BASE64="/usr/bin/base64"
MKDIR="/usr/bin/mkdir"
MV="/bin/mv"
RM="/bin/rm"
CHOWN="/bin/chown"
CHMOD="/bin/chmod"
SYSTEMCTL="/bin/systemctl"
DATE="/bin/date"

# Temp file
TMPFILE=$(/usr/bin/mktemp /tmp/vault-k8s.crt.XXXXXX)

# -------------------------------
# Fetch and decode TLS cert
# -------------------------------
$KUBECTL get secret "$SECRET" -n "$NAMESPACE" -o jsonpath='{.data.tls\.crt}' | $BASE64 -d > "$TMPFILE"

# -------------------------------
# Compare with current cert
# -------------------------------
if [ -f "$DEST" ]; then
    if /usr/bin/cmp -s "$TMPFILE" "$DEST"; then
        echo "$($DATE): Cert unchanged, nothing to do."
        $RM "$TMPFILE"
        exit 0
    fi
fi

# -------------------------------
# Update cert
# -------------------------------
echo "$($DATE): Cert changed, updating..."
$RM -f "$DEST"
$MV "$TMPFILE" "$DEST"
# $CHOWN "$USER:$GROUP" "$DEST"
$CHMOD 644 "$DEST"

# -------------------------------
# Reload Vault to pick up new cert
# -------------------------------
if $SYSTEMCTL is-active --quiet "$VAULT_SERVICE"; then
    $SYSTEMCTL reload "$VAULT_SERVICE"
    echo "$($DATE): Vault reloaded."
else
    echo "$($DATE): Vault not running, skipping reload."
fi

```

Add the cronjob:
```
crontab -e

...

0 2 * * * /home/administrator/Kubernetes/CronJobs/CertRotations/rotate-vault-k8s-crt.sh >> /home/administrator/vault-cert-rotate.log 2>&1

```

DONE
