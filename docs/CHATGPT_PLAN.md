# ChatGPT plan profile in this ARTEX fork

This fork adds a `chatgpt-plan` LLM profile. It uses OpenAI's documented Sign in with ChatGPT OAuth flow and the public Responses API. It never reads Codex or ChatGPT cookies, session files, or API keys. The ARTEX admin login is still separate from ChatGPT sign-in.

## Local setup

1. Build this checkout with the smaller local image. Use `cp .env.example .env`, set a new `POSTGRES_PASSWORD`, and run `docker compose -f docker-compose.yml -f docker-compose.plan-local.yml up -d --build`. Do not use `install.sh` for this route; it can install Docker and other software. The local image omits the standard image's third-party scanner installers and mounts only ARTEX's data, keys, and read-only skills. It has Bash, curl, nmap, jq, and Python for a first scoped run.
2. Open `http://127.0.0.1:8787`, complete ARTEX's own first-run setup, then go to **System → LLM**.
3. Click **Continue with ChatGPT**. Approve the ARTEX registration in your browser. The callback returns to `http://127.0.0.1:8787/api/auth/siwc/callback`.
4. Create a **ChatGPT plan (sign in)** profile. Click **Load models** to get the signed-in account's visible model list, choose a model such as `gpt-6-sol`, and **Test connection**. Activate the profile only after the test succeeds.
5. If your account has Daybreak approval, click **Request Daybreak Blue**, then test the selected model again. The switch adds `access_programs.cyber=daybreak_blue`; it cannot grant approval. OpenAI may reject the request if ChatGPT plan OAuth access does not carry the required Daybreak entitlement. `gpt-6-sol` is the first model to try; reduced refusals on newer Sol models can require Daybreak Red approval.

The access and rotating refresh tokens are stored in `keys/chatgpt-plan.json`, written atomically with mode `0600` and never returned by the ARTEX API. `keys/` is excluded from Git and is mounted only into the ARTEX container. Signing out asks OpenAI to revoke the refresh token and clears local tokens. If revocation cannot be confirmed, the UI says so; disconnect ARTEX from ChatGPT Settings as needed.
Run one ARTEX server against a given `keys/` directory; refresh serialization is within that server process.

## Network and data boundaries

The plan integration contacts only these fixed OpenAI endpoints:

| Purpose | Destination |
| --- | --- |
| Browser authorization, code exchange, refresh, revocation, ID-token keys | `auth.openai.com` |
| Account model list and inference | `api.openai.com/v1/models`, `api.openai.com/v1/responses` |

Plan inference is pinned to HTTPS `api.openai.com/v1/responses`, uses `store:false` and `stream:true`, and cannot use a profile-supplied base URL or proxy. Its bearer token is injected when the request is sent. The provider groups ARTEX functions in an `artex` namespace and omits `max_output_tokens` and `temperature`, which the ChatGPT plan route does not support. Model prompts can include ARTEX's locally recorded target requests and responses, so use test accounts and remove secrets you do not want sent to OpenAI.

The rest of ARTEX retains its normal capabilities: agents can run shell tools and send target traffic; optional web search, notification webhooks, external MCP servers and `ARTEX_UPDATE_CHECK=1` add other outbound destinations. The browser extension and traffic proxy can record headers and bodies, including authentication material. The standard Dockerfile downloads additional toolchain components during build; the local image above avoids those installers. A source review and fixed LLM destination do not prove that every dependency or agent action is harmless. Keep ARTEX in its own container with only `data/`, `keys/`, and `skills/` mounted, and leave the update check, notifications, web search, and external MCP disabled until wanted.

## Testing a local app

Start with a staging environment or test account. Enable ARTEX's target gate, use an exact target origin, set `ARTEX_NOISE_PROFILE=quiet`, and set task/intent budgets before starting autonomous work. Bash-launched scanner traffic is not covered by the noise governor, so run a narrowly scoped first task and inspect its command log. Avoid broad network or production data access.

The app at `http://127.0.0.1:3000` is on the Mac host. A Docker container's own `127.0.0.1` is the container, so ARTEX will need a deliberately scoped host-to-container forwarding path before its workers can reach that app. Do not change the app's WorkOS callback address to make the container reach it. The ChatGPT connection and model test can be completed before any target forwarding is set up.

## Verification and current limits

The fork has Go tests for request shaping, destination pinning, PKCE sign-in parameters, protected credential storage, signed ID-token validation, and concurrent refresh. The Go packages compile and the static Next.js frontend builds. The actual OpenAI sign-in, plan inference, Daybreak entitlement, and a live ARTEX scan require the user's browser authorization and have not yet been exercised.
The smaller image uses the checked-in lockfile. Its production dependency audit has no reported advisories after updating Zod, source-map-js, and baseline-browser-mapping. The full development/build dependency tree still has advisories, so avoid exposing a development server to other machines.

At runtime, one inference makes one outbound Responses request and sends the local transcript history, so request size and memory grow with retained history `H`. Refresh makes one token endpoint call near expiry, serialized across workers, and rewrites the local account file in `O(A)` space for `A` saved accounts. Model listing makes one API call and holds `O(M)` model entries. No database query is added per inference by this integration; ARTEX's existing recording and task logic still has its own costs.
