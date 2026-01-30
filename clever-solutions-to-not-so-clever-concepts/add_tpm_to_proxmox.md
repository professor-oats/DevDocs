## Add TPM to Proxmox ##

To enable vTPM in Proxmox this guide will go through each step.

### Step one - Check the requirements ###

2. Proxmox host prerequisites

On the Proxmox node hosting VM 100:

pveversion


You need:

Proxmox 7.4+ (8.x preferred)

QEMU 7+

swtpm installed (usually already present)

Verify:

```
dpkg -l | grep swtpm
```

If missing:

```
apt update && apt install swtpm swtpm-tools
```


### Step two - Add TPM 2.0 device to VM 100 ###

Using CLI (recommended for auditability)
```
root@pve:~# qm set 100 --tpmstate0 vmdata:1,version=v2.0
update VM 100: -tpmstate0 vmdata:1,version=v2.0
tpmstate0: successfully created disk 'vmdata:vm-100-disk-2,size=4M,version=v2.0'
root@pve:~# 

```


What this does:

Creates persistent TPM state

Uses TPM 2.0

Stores TPM data in Proxmox vmdata storage, which will include the state in the VM 100 snapshots

Verify:
```
qm config 100 | grep -i tpm
```

You should see:
```
tpmstate0: local-lvm:vm-100-disk-TPM,size=1M,version=v2.0
```

### Step three - Firmware requirement (CRITICAL) ###

TPM requires UEFI.

Verify VM firmware:
```
qm config 100 | grep bios
```

If not ovmf, fix it:

```
qm set 100 --bios ovmf
qm set 100 --efidisk0 vmdata:0
```


⚠️ Do this before OS install if possible
Changing firmware post-install may break boot.


### Step four - Start VM and validate TPM presence ###

Boot VM 100 and run inside Ubuntu:

```
ls -l /dev/tpm*
```

Expected:

```
/dev/tpm0
/dev/tpmrm0
```

If missing, check kernel:

```
dmesg | grep -i tpm
```


### Step five - Install TPM tooling inside Ubuntu ###

```
sudo apt update
sudo apt-get install tpm2-tools libtss2-dev libtss2-esys-3.0.2-0t64 libtss2-tcti-swtpm0t64
```

Verify TPM access:

```
sudo tpm2_getcap properties-fixed
sudo tpm2_getrandom 8
sudo tpm2_pcrread
```

If this works, TPM is operational.

### Step six - Use the TPM ###
### Before - Shortly about the handle format of TPM ###

```
TPM 2.0 persistent handle format

A persistent handle is a 32-bit value with this structure:

0x81TTIIII

Breakdown
Field	Bits	Meaning
0x81	8	Persistent handle namespace
TT	8	Reserved / TPM-defined (almost always 01)
IIII	16	Index you choose

So your example:

0x81010001

means:

0x81 → persistent object

0x01 → standard persistent range

0x0001 → your chosen index
```

### Implement ###

```
🛠 Step-by-Step Implementation
1️⃣ Initialize Vault normally (once)
vault operator init -key-shares=5 -key-threshold=3


You get:

5 unseal keys

1 root token

⚠️ Do this offline, copy results securely, then immediately move to TPM sealing.

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

### Usage ###

Now it's ready to be decrypted using the unseal.blob + iv.bin
Example usage in script:

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

DONE
