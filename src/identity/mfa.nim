#[
===
mfa
===
Multi-factor authentication: TOTP, recovery codes, OIDC, SAML, session, federation.
]#
import basis/code/throw
standard_pragmas(effects=false, rise=false)
import std/[strutils, tables, hashes, random, json, base64, uri, xmltree]

type
  MfaMethod* = enum mmTotp, mmRecoveryCodes
  TotpConfig* = object
    secret*: string
    digits*: int
    period*: int
  RecoveryCodeSet* = object
    codes*: seq[string]
    usedCodes*: seq[string]
  SessionState* = enum ssActive, ssExpired, ssLocked, ssPendingMfa
  Session* = object
    id*: string
    userId*: string
    createdAt*: string
    lastActivity*: string
    expiresAt*: string
    state*: SessionState
    mfaVerified*: bool
    ipAddress*: string
    userAgent*: string
    roles*: seq[string]
  SessionPolicy* = object
    idleTimeoutSec*: int
    absoluteTimeoutSec*: int
    maxConcurrent*: int
    requireMfaFor*: seq[string]
    bindToIp*: bool
  OidcAuthRequest* = object
    clientId*: string
    redirectUri*: string
    scope*: string
    state*: string
    nonce*: string
  IdTokenClaims* = object
    iss*: string
    sub*: string
    aud*: string
    exp*: int64
    iat*: int64
    nonce*: string
    email*: string
    name*: string
  SamlSpConfig* = object
    entityId*: string
    assertionConsumerUrl*: string
  SamlIdpConfig* = object
    entityId*: string
    ssoUrl*: string
  SamlAssertion* = object
    issuer*: string
    subjectNameId*: string
    attributes*: Table[string, seq[string]]
    sessionIndex*: string
  ClaimMapping* = object
    externalClaim*: string
    internalField*: string
  FederationConfig* = object
    mappings*: seq[ClaimMapping]
    defaultRoles*: seq[string]
    autoProvision*: bool
  FederatedIdentity* = object
    externalId*: string
    provider*: string
    internalId*: string
    roles*: seq[string]
    attributes*: Table[string, string]

# TOTP
proc generateSecret*(length: int = 20): string =
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  var rng = initRand(42)
  for i in 0 ..< length: result.add(chars[rng.rand(chars.len - 1)])

proc computeTotp*(secret: string, timestamp: int64, period: int = 30, digits: int = 6): string =
  let counter = timestamp div period
  var h: Hash = 0
  h = h !& hash(secret)
  h = h !& hash(counter)
  var modulus = 1
  for i in 0 ..< digits: modulus *= 10
  let code = abs(!$h) mod modulus
  result = align($code, digits, '0')

proc validateTotp*(secret: string, code: string, timestamp: int64, period: int = 30, window: int = 1): bool =
  for offset in -window .. window:
    if computeTotp(secret, timestamp + offset * period, period) == code: return true
  false

# Recovery codes
proc generateRecoveryCodes*(count: int = 10, length: int = 8): RecoveryCodeSet =
  var rng = initRand(42)
  for i in 0 ..< count:
    var code = ""
    for j in 0 ..< length: code.add(chr(rng.rand(25) + ord('A')))
    result.codes.add(code)

proc useRecoveryCode*(codes: var RecoveryCodeSet, code: string): bool =
  let idx = codes.codes.find(code)
  if idx >= 0:
    codes.usedCodes.add(code)
    codes.codes.delete(idx)
    return true
  false

# Session
func defaultPolicy*(): SessionPolicy =
  SessionPolicy(idleTimeoutSec: 900, absoluteTimeoutSec: 28800, maxConcurrent: 3, bindToIp: true)

func requiresReauth*(session: Session, operation: string, policy: SessionPolicy): bool =
  operation in policy.requireMfaFor and not session.mfaVerified

proc touch*(session: var Session, currentTime: string) =
  session.lastActivity = currentTime

# OIDC
func buildOidcAuthUrl*(authorizeEndpoint: string, req: OidcAuthRequest): string =
  var qs: seq[string]
  qs.add("response_type=code")
  qs.add("client_id=" & encodeUrl(req.clientId))
  qs.add("redirect_uri=" & encodeUrl(req.redirectUri))
  qs.add("scope=" & encodeUrl(req.scope))
  qs.add("state=" & req.state)
  qs.add("nonce=" & req.nonce)
  authorizeEndpoint & "?" & qs.join("&")

proc parseIdTokenClaims*(idToken: string): IdTokenClaims =
  let parts = idToken.split('.')
  if parts.len >= 2:
    let payload = decode(parts[1] & "==")  # pad base64
    let j = parseJson(payload)
    result.iss = j.getOrDefault("iss").getStr()
    result.sub = j.getOrDefault("sub").getStr()
    result.aud = j.getOrDefault("aud").getStr()
    result.email = j.getOrDefault("email").getStr()
    result.name = j.getOrDefault("name").getStr()
    result.nonce = j.getOrDefault("nonce").getStr()

func validateIdToken*(claims: IdTokenClaims, expectedIss, expectedAud, expectedNonce: string): bool =
  claims.iss == expectedIss and claims.aud == expectedAud and claims.nonce == expectedNonce

# SAML
func buildAuthnRequest*(sp: SamlSpConfig, idp: SamlIdpConfig, requestId, issueInstant: string): string =
  ## Build SAML AuthnRequest via std/xmltree (proper XML generation, not string concat).
  var req = newElement("samlp:AuthnRequest")
  req.attrs = {"ID": requestId, "IssueInstant": issueInstant,
               "Destination": idp.ssoUrl,
               "AssertionConsumerServiceURL": sp.assertionConsumerUrl,
               "xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
               "xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
               "Version": "2.0"}.toXmlAttributes
  var issuer = newElement("saml:Issuer")
  issuer.add(newText(sp.entityId))
  req.add(issuer)
  $req

func mapAttributes*(assertion: SamlAssertion, mapping: Table[string, string]): Table[string, string] =
  for ext, intField in mapping:
    if ext in assertion.attributes and assertion.attributes[ext].len > 0:
      result[intField] = assertion.attributes[ext][0]

# Federation
func mapClaims*(config: FederationConfig, externalClaims: Table[string, string]): Table[string, string] =
  for m in config.mappings:
    if m.externalClaim in externalClaims:
      result[m.internalField] = externalClaims[m.externalClaim]

func provision*(config: FederationConfig, externalClaims: Table[string, string], provider: string): FederatedIdentity =
  let mapped = mapClaims(config, externalClaims)
  result.provider = provider
  result.externalId = externalClaims.getOrDefault("sub", "")
  result.roles = config.defaultRoles
  result.attributes = mapped
