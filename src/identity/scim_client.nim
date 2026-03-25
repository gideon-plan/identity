## scim_client.nim -- SCIM 2.0 REST client.
{.experimental: "strict_funcs".}

import basis/code/choice
import httpc/curl_client

type
  ScimUser* = object
    id*: string
    username*: string
    display_name*: string
    groups*: seq[string]

  ScimGroup* = object
    id*: string
    display_name*: string
    members*: seq[string]

  ScimClient* = object
    base_url*: string
    http*: CurlClient
    token*: string

proc init_scim_client*(base_url: string, token: string = ""): Choice[ScimClient] =
  let cc = init_curl_client()
  if cc.is_bad: return bad[ScimClient]("identity", "failed to init curl")
  good(ScimClient(base_url: base_url, http: cc.val, token: token))

proc close*(c: var ScimClient) =
  c.http.close()

proc auth_headers(c: ScimClient): seq[(string, string)] =
  if c.token.len > 0:
    @[("Authorization", "Bearer " & c.token)]
  else:
    @[]

proc list_users*(c: ScimClient): Choice[string] =
  let r = c.http.get(c.base_url & "/Users", c.auth_headers())
  if r.is_bad: return bad[string](r.err)
  good(r.val.body)

proc list_groups*(c: ScimClient): Choice[string] =
  let r = c.http.get(c.base_url & "/Groups", c.auth_headers())
  if r.is_bad: return bad[string](r.err)
  good(r.val.body)
