--
-- e2ee_attest.lua - Verify a TEE instance before encrypting to its key.
--
-- Discovery hands out e2e_pubkeys; without attestation the proxy would encrypt
-- to whatever key it is given, including one the control plane substitutes.
-- Before a key is used, confirm its quote: DCAP-valid, report_data bound to the
-- key, non-debug, golden MRTD. Fails closed. Mirrors verify_chute.py.
--

local http = require("resty.http")
local cjson = require("cjson.safe")
local sha256 = require("resty.sha256")
local str = require("resty.string")
local random = require("resty.random")
local crypto = require("e2ee_crypto")

local _M = {}

local API_BASE = "https://api.chutes.ai"
function _M.set_api_base(base) API_BASE = base end

-- Without pinned goldens we cannot tell a genuine Chutes image from an
-- attacker's real-but-arbitrary TD, so an empty allowlist is a hard failure.
local function golden_mrtds()
    local raw = os.getenv("CHUTES_GOLDEN_MRTD")
    if not raw or raw == "" then return nil end
    local set = {}
    for hex in raw:gmatch("[^,%s]+") do set[hex:lower()] = true end
    return set
end

local attest_disabled = os.getenv("CHUTES_DISABLE_ATTESTATION") == "true"

local function bind_hash(nonce, e2e_pubkey)
    local h = sha256:new()
    h:update(nonce)
    h:update(e2e_pubkey)
    return str.to_hex(h:final())
end

local function fetch_evidence(chute_id, nonce, api_key)
    local httpc = http.new()
    httpc:set_timeout(15000)
    local res, err = httpc:request_uri(
        API_BASE .. "/chutes/" .. chute_id .. "/evidence",
        {
            method = "GET",
            query = { nonce = nonce },
            headers = { ["Authorization"] = "Bearer " .. api_key },
            ssl_verify = true,
        }
    )
    if not res then return nil, "evidence request failed: " .. (err or "unknown") end
    if res.status ~= 200 then
        return nil, "evidence returned " .. res.status .. ": " .. (res.body or ""):sub(1, 200)
    end
    local data = cjson.decode(res.body)
    if not data or not data.evidence then return nil, "invalid evidence response" end

    local by_id = {}
    for _, e in ipairs(data.evidence) do
        if e.instance_id then by_id[e.instance_id] = e end
    end
    return by_id
end

local function verify_instance(ev, expected_pubkey, nonce, goldens)
    if not ev or not ev.quote then return nil, "no quote in evidence" end

    local report, err = crypto.verify_td_quote(ev.quote)
    if not report then return nil, "quote verification failed: " .. (err or "unknown") end

    if report.report_data:sub(1, 64) ~= bind_hash(nonce, expected_pubkey) then
        return nil, "report_data mismatch: pubkey not bound to attested enclave"
    end
    if report.debug then return nil, "TD is in debug mode" end
    if not goldens[report.mrtd] then return nil, "MRTD not in golden allowlist" end
    return true
end

-- Return the subset of `instances` whose e2e_pubkey is attestation-verified.
-- nil + reason on a hard error (so the caller fails closed).
function _M.filter_verified(chute_id, instances, api_key)
    if attest_disabled then
        ngx.log(ngx.WARN, "CHUTES_DISABLE_ATTESTATION=true: encrypting to unverified ",
                "keys; confidentiality vs the control plane is NOT guaranteed")
        return instances
    end

    local goldens = golden_mrtds()
    if not goldens then
        return nil, "no golden MRTD pinned (set CHUTES_GOLDEN_MRTD); refusing to "
            .. "encrypt without attestation. Set CHUTES_DISABLE_ATTESTATION=true to override."
    end

    local rand = random.bytes(32, true)
    if not rand then return nil, "CSPRNG failed to produce attestation nonce" end
    local nonce = str.to_hex(rand)

    local evidence, err = fetch_evidence(chute_id, nonce, api_key)
    if not evidence then return nil, err end

    local verified = {}
    for _, inst in ipairs(instances) do
        local ok, reason = verify_instance(
            evidence[inst.instance_id], inst.e2e_pubkey, nonce, goldens
        )
        if ok then
            verified[#verified + 1] = inst
        else
            ngx.log(ngx.WARN, "dropping unverified instance ", inst.instance_id,
                    " for chute ", chute_id, ": ", reason)
        end
    end
    return verified
end

return _M
