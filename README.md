# appbuild-master

Simple automation helpers for **Palo Alto PAN-OS** tasks.

## Included operations

The `palo_alto_ops.py` CLI currently supports:

1. `create-rule` - create or update a firewall security rule.
2. `url-whitelist` - create/update a custom URL category and allow it in an existing URL filtering profile (egress whitelist behavior).

## Usage

### 1) Create firewall rule

```bash
python3 palo_alto_ops.py \
  --host 10.0.0.10 \
  --username admin \
  --password '***' \
  --vsys vsys1 \
  create-rule \
  --name Allow-Sales-to-SaaS \
  --from-zones trust \
  --to-zones untrust \
  --source-addresses 10.20.30.0/24 \
  --destination-addresses any \
  --applications web-browsing,ssl \
  --services application-default \
  --action allow \
  --description "Sales outbound web access" \
  --commit
```

### 2) URL egress whitelist

```bash
python3 palo_alto_ops.py \
  --host 10.0.0.10 \
  --username admin \
  --password '***' \
  --vsys vsys1 \
  url-whitelist \
  --category-name egress-allowlist \
  --profile-name Corp-URL-Profile \
  --urls '*.github.com,api.slack.com,login.microsoftonline.com' \
  --commit
```

## Notes

- By default SSL cert verification is enabled; add `--insecure` if needed for lab/self-signed devices.
- The script uses PAN-OS XML API and auto-generates an API key via username/password.
- `url-whitelist` expects the URL filtering profile already exists.
