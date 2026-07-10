---
name: verify
description: Drive this Terraform provider end-to-end without a real UniFi controller, using dev_overrides and a mock controller.
---

# Verifying terraform-provider-unifi changes

Acceptance tests (`make testacc`, testcontainers) don't cover zone-based
firewall features — the dockerized controller doesn't support them. To observe
a schema/resource change at the real surface, drive the compiled provider with
the Terraform CLI against a mock controller.

## Recipe

1. **Terraform binary**: the checkpoint API is blocked by the proxy, so
   tfplugindocs/`terraform` can't auto-download. Fetch directly (pick a
   version): `curl -sSLo tf.zip https://releases.hashicorp.com/terraform/1.15.8/terraform_1.15.8_linux_amd64.zip && unzip tf.zip`.
   Use **1.15+**: older binaries don't know list-resource/action schemas and
   `go generate ./...` (tfplugindocs) will *delete* `docs/list-resources/` and
   `docs/actions/` with them.

2. **Build + dev override**:
   ```
   go build -o <dir>/terraform-provider-unifi .
   ```
   CLI config (`TF_CLI_CONFIG_FILE=dev.tfrc`):
   ```hcl
   provider_installation {
     dev_overrides { "ubiquiti-community/unifi" = "<dir>" }
     direct {}
   }
   ```
   Skip `terraform init`; run `validate`/`plan`/`apply` directly.

3. **`terraform validate`** exercises schema + validators (including
   resource-level `ConfigValidators`) with no controller at all.

4. **Mock controller** for plan/apply: `api_key` auth skips the login flow, so
   a plain-HTTP catch-all server works:
   ```hcl
   provider "unifi" {
     api_key        = "mock"
     api_url        = "http://127.0.0.1:8089"
     site           = "default"
     allow_insecure = true
   }
   ```
   The mock must: store POSTed objects and echo them back with a generated
   `_id` **and an `index`** (firewall policies fail "invalid result object
   after apply" without one, since `index` is Computed); return the stored
   list on GET (`getX` filters the list client-side); echo PUT bodies; answer
   site lookups (`.../self/sites`) with
   `{"meta":{"rc":"ok"},"data":[{"_id":"s1","name":"default"}]}`.
   Give each POST a **unique** `_id` or refreshes cross-contaminate.

5. Log every request body in the mock — the captured JSON is the evidence
   that a field actually reaches the wire. After apply, run `terraform plan`
   again: it must report "No changes" (perpetual-diff check).
