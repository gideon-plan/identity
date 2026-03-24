{.experimental: "strict_funcs".}
import std/[unittest, tables]
import identity
suite "ldap_proto":
  test "encode/decode string":
    let encoded = encode_string("hello")
    var pos = 0
    let decoded = decode_ber(encoded, pos)
    check decoded.tag == tagOctetString
    check decoded.data == "hello"
  test "encode/decode integer":
    let encoded = encode_integer(42)
    var pos = 0
    let decoded = decode_ber(encoded, pos)
    check decoded.tag == tagInteger
  test "encode/decode sequence":
    let seq_data = encode_sequence(@[encode_string("a"), encode_string("b")])
    var pos = 0
    let decoded = decode_ber(seq_data, pos)
    check decoded.tag == tagSequence
  test "length encoding":
    let short_len = encode_length(50)
    check short_len.len == 1
    let long_len = encode_length(200)
    check long_len.len == 2
suite "ldap_client":
  test "bind simple":
    var sent = ""
    let mock_send: LdapSendFn = proc(d: string): Result[void, BridgeError] {.raises: [].} =
      sent = d; Result[void, BridgeError](ok: true)
    let mock_recv: LdapRecvFn = proc(): Result[string, BridgeError] {.raises: [].} =
      Result[string, BridgeError].good("ok")
    var c = new_ldap_client(mock_send, mock_recv)
    let r = c.bind_simple("cn=admin", "password")
    check r.is_good
    check c.bound
suite "scim_client":
  test "list users":
    let mock_http: HttpGetFn = proc(u: string): Result[string, BridgeError] {.raises: [].} =
      Result[string, BridgeError].good("{\"Resources\": []}")
    let c = new_scim_client("http://localhost/scim", mock_http)
    let r = c.list_users()
    check r.is_good
suite "sync":
  test "sync entries":
    var added: seq[string]
    let mock_add: AddEntityFn = proc(et, id: string, a: Table[string, string]): Result[void, BridgeError] {.raises: [].} =
      added.add(id); Result[void, BridgeError](ok: true)
    let entries = @[LdapEntry(dn: "cn=alice", attributes: {"cn": @["alice"]}.toTable)]
    let r = sync_ldap_entries(entries, mock_add)
    check r.is_good
    check r.val.users_synced == 1
