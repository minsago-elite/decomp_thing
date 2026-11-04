# Explicit local limits for ChatGPT-plan runs

Product decision adopted on 2026-11-05: users may explicitly select locally bounded ChatGPT-plan inference even when the provider cannot enforce a server-side output-token cap. Existing providers' token-cap contracts remain unchanged.

The supported policy is `local-acceptance-v1` (`chatgpt-local-acceptance-v1` in the integration design). Each run must explicitly select its account, returned model slug and this budget policy. Selecting the harness alone, an environment credential or an unrelated previous run does not elect the policy. Queued jobs and resumed work must retain and validate that selection and the applicable policy/limit commitments.

Before starting, the interface must explain the actual guarantee in plain language:

> This run uses your selected ChatGPT plan. Local limits bound elapsed time, requests, received bytes and tool actions. They do not enforce a server-side output-token ceiling or guarantee total plan consumption, including hidden reasoning. Stopping locally may not stop server work. The run will not switch to API-key billing.

Local input/output accounting units are estimates, not server tokens. Local request, response, event, context, continuation, display and evidence byte limits, request/tool counts, retries, cancellation and deadlines remain mandatory. Reported provider usage must retain its provenance; unavailable usage is unknown, not zero. A local stop must report the actual stop reason and settlement state, without claiming that remote processing has stopped.

A caller requiring a server-enforced output-token cap must still be refused by a provider that cannot supply it. Do not convert existing `maxOutputTokens` fields or existing provider defaults into local estimates, silently downgrade a strict request, or fall back to another account, model, provider, ACP or API-key identity. The v1 provider contract stays unchanged; the separate v2 capability/admission boundary carries the explicit local election.

This decision authorizes the supported product mode; it does not enable an unfinished provider. Production registration still requires reviewed account/authentication and HTTP ownership, model eligibility, bounded complete-context streaming, secret handling, host-controlled tool settlement, durable continuation, capture/evidence integration and exact-source installed/live qualification. Authentication, account/model selection, local-limit election, streaming, cancellation, recoverable failure and continuation must also be verified together for usable operation. No issue acceptance is established merely by adopting this policy.
