# Viper

Viper is a configuration generator and remote harness for a VPN stack: Xray/VLESS/REALITY.

## Project goal

Provide easy way to store and manage configuration generator, that allows to deploy a vpn server on a freshly provisioned VPS with root access.

## Additional documentation

Context-specific source material can be found in `refs/`

## Operating rules

- **Escalate environment blockers.** When a host-level dependency or permission is missing (tools, sudo, system packages), stop and ask — present the options (user installs it, grants access, or explicitly approves a workaround). Never install workarounds into the user's environment unilaterally.

## UX

1. [User] provision VPS and set up root access with a key
2. [User] configure template variables and run `deploy --ip xxx`
3. [Viper] generate Xray config and Happ Proxy compatible subscription file
4. [Viper] remotely log into the server, harden the environment, install dependencies, configure Xray, show the user the page with a simple observability ui and a link to add a Happ subscription