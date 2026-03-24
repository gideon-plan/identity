## scim_client.nim -- SCIM 2.0 REST client.
{.experimental: "strict_funcs".}

import lattice
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
  HttpGetFn* = proc(url: string): Result[string, BridgeError] {.raises: [].}
  ScimClient* = object
    base_url*: string
    http_fn*: HttpGetFn
    token*: string
proc new_scim_client*(base_url: string, http_fn: HttpGetFn, token: string = ""): ScimClient =
  ScimClient(base_url: base_url, http_fn: http_fn, token: token)
proc list_users*(c: ScimClient): Result[string, BridgeError] =
  c.http_fn(c.base_url & "/Users")
proc list_groups*(c: ScimClient): Result[string, BridgeError] =
  c.http_fn(c.base_url & "/Groups")
