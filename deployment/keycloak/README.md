# Keycloak realm import

The NETRA development realm (`netra-realm.json`) is added in **Phase 2**, when
OIDC authentication is implemented. It will define:

- realm `netra`
- confidential client `netra-backend` (token audience)
- public client `netra-client` for the Electron app (authorization code + PKCE)
- roles `USER`, `SECURITY_ANALYST`, `ADMIN`, `AUDITOR`
- the simulated users used by the demo

The realm is committed as an import file so that the identity provider is
reproducible and the demo does not depend on manual console configuration.

Start the identity profile with:

```bash
docker compose -f deployment/compose/docker-compose.yml --profile identity up
```
