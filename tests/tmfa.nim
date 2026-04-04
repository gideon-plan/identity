{.experimental: "strictFuncs".}
import std/[unittest, tables, strutils]
import identity/mfa
suite "TOTP":
  test "generate secret": check generateSecret().len == 20
  test "compute totp": check computeTotp("TESTSECRET", 1000000, 30, 6).len == 6
  test "validate totp":
    let secret = "TESTSECRET"
    let ts: int64 = 1000000
    let code = computeTotp(secret, ts)
    check validateTotp(secret, code, ts)
  test "totp window":
    let secret = "TESTSECRET"
    let ts: int64 = 1000000
    let code = computeTotp(secret, ts)
    check validateTotp(secret, code, ts + 15, window = 1)
suite "Recovery codes":
  test "generate": check generateRecoveryCodes(10).codes.len == 10
  test "use code":
    var codes = generateRecoveryCodes(5)
    let c = codes.codes[0]
    check useRecoveryCode(codes, c)
    check codes.codes.len == 4
    check codes.usedCodes.len == 1
  test "invalid code":
    var codes = generateRecoveryCodes(5)
    check not useRecoveryCode(codes, "INVALID")
suite "Session":
  test "default policy":
    let p = defaultPolicy()
    check p.idleTimeoutSec == 900
  test "requires reauth":
    let s = Session(mfaVerified: false)
    let p = SessionPolicy(requireMfaFor: @["delete_patient"])
    check requiresReauth(s, "delete_patient", p)
    check not requiresReauth(s, "read_patient", p)
suite "OIDC":
  test "build auth url":
    let url = buildOidcAuthUrl("https://auth.example.com/authorize",
      OidcAuthRequest(clientId: "c1", redirectUri: "https://app/cb", scope: "openid", state: "s1", nonce: "n1"))
    check "client_id=c1" in url
  test "validate id token":
    let claims = IdTokenClaims(iss: "https://idp.example.com", aud: "client1", nonce: "n1")
    check validateIdToken(claims, "https://idp.example.com", "client1", "n1")
    check not validateIdToken(claims, "https://other.com", "client1", "n1")
suite "SAML":
  test "build authn request":
    let xml = buildAuthnRequest(
      SamlSpConfig(entityId: "https://sp.example.com", assertionConsumerUrl: "https://sp.example.com/acs"),
      SamlIdpConfig(entityId: "https://idp.example.com", ssoUrl: "https://idp.example.com/sso"),
      "req-1", "2024-01-01T00:00:00Z")
    check "AuthnRequest" in xml
    check "req-1" in xml
  test "map attributes":
    let assertion = SamlAssertion(attributes: {"email": @["user@example.com"], "name": @["John"]}.toTable)
    let mapped = mapAttributes(assertion, {"email": "mail", "name": "displayName"}.toTable)
    check mapped["mail"] == "user@example.com"
suite "Federation":
  test "map claims":
    let config = FederationConfig(mappings: @[ClaimMapping(externalClaim: "email", internalField: "mail")])
    let mapped = mapClaims(config, {"email": "user@example.com"}.toTable)
    check mapped["mail"] == "user@example.com"
  test "provision":
    let config = FederationConfig(defaultRoles: @["viewer"],
      mappings: @[ClaimMapping(externalClaim: "email", internalField: "mail")])
    let identity = provision(config, {"sub": "ext-123", "email": "u@ex.com"}.toTable, "okta")
    check identity.provider == "okta"
    check identity.roles == @["viewer"]
