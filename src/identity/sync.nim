## sync.nim -- Sync users/groups into porta entity store.
{.experimental: "strict_funcs".}
import std/tables
import basis/code/choice, ldap_client
type
  AddEntityFn* = proc(entity_type, id: string, attrs: Table[string, string]): Choice[bool] {.raises: [].}
  SyncResult* = object
    users_synced*: int
    groups_synced*: int
proc sync_ldap_entries*(entries: seq[LdapEntry], add_fn: AddEntityFn
                       ): Choice[SyncResult] =
  var sr: SyncResult
  for entry in entries:
    var attrs: Table[string, string]
    for k, vs in entry.attributes:
      if vs.len > 0: attrs[k] = vs[0]
    let entity_type = if "objectClass" in entry.attributes and
                        "group" in entry.attributes["objectClass"]: "Group"
                      else: "User"
    let r = add_fn(entity_type, entry.dn, attrs)
    if r.is_bad: continue
    if entity_type == "User": inc sr.users_synced
    else: inc sr.groups_synced
  good(sr)
