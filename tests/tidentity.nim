{.experimental: "strict_funcs".}
import std/[unittest, tables]
import basis/code/choice
import identity/ldap_proto
import identity/ldap_client
import identity/scim_client
import identity/sync

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
    let mock_send: LdapSendFn = proc(d: string): Choice[bool] {.raises: [].} =
      sent = d; good(true)
    let mock_recv: LdapRecvFn = proc(): Choice[string] {.raises: [].} =
      good("ok")
    var c = new_ldap_client(mock_send, mock_recv)
    let r = c.bind_simple("cn=admin", "password")
    check r.is_good
    check c.bound

suite "scim_client":
  test "init and close":
    let r = init_scim_client("http://localhost/scim")
    check r.is_good
    var c = r.val
    c.close()

suite "sync":
  test "sync entries":
    var added: seq[string]
    let mock_add: AddEntityFn = proc(et, id: string, a: Table[string, string]): Choice[bool] {.raises: [].} =
      added.add(id); good(true)
    let entries = @[LdapEntry(dn: "cn=alice", attributes: {"cn": @["alice"]}.toTable)]
    let r = sync_ldap_entries(entries, mock_add)
    check r.is_good
    check r.val.users_synced == 1
