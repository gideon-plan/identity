## ldap_client.nim -- LDAP TCP client (bind, search, unbind).
{.experimental: "strict_funcs".}
import std/tables
import basis/code/choice, ldap_proto
type
  LdapEntry* = object
    dn*: string
    attributes*: Table[string, seq[string]]
  LdapSendFn* = proc(data: string): Choice[bool] {.raises: [].}
  LdapRecvFn* = proc(): Choice[string] {.raises: [].}
  LdapClient* = object
    send_fn*: LdapSendFn
    recv_fn*: LdapRecvFn
    bound*: bool
    message_id*: int
proc new_ldap_client*(send_fn: LdapSendFn, recv_fn: LdapRecvFn): LdapClient =
  LdapClient(send_fn: send_fn, recv_fn: recv_fn)
proc bind_simple*(c: var LdapClient, dn, password: string): Choice[bool] =
  inc c.message_id
  let msg = encode_sequence(@[encode_integer(c.message_id),
    encode_ber(0x60, encode_integer(3) & encode_string(dn) & encode_ber(0x80, password))])
  let r = c.send_fn(msg)
  if r.is_bad: return r
  let resp = c.recv_fn()
  if resp.is_bad: return bad[bool](resp.err)
  c.bound = true
  good(true)
proc unbind*(c: var LdapClient): Choice[bool] =
  inc c.message_id
  c.send_fn(encode_sequence(@[encode_integer(c.message_id), encode_ber(0x42, "")]))
