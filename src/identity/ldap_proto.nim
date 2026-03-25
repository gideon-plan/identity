## ldap_proto.nim -- LDAP protocol codec (BER/DER encoding).
{.experimental: "strict_funcs".}
import basis/code/choice

type
  BridgeError* = object of CatchableError

type
  BerTag* = uint8
  BerClass* = enum bcUniversal, bcApplication, bcContext, bcPrivate
  BerValue* = object
    tag*: BerTag
    data*: string
const
  tagInteger*    = 0x02'u8
  tagOctetString* = 0x04'u8
  tagSequence*   = 0x30'u8
  tagSet*        = 0x31'u8
  tagEnum*       = 0x0A'u8
  tagBoolean*    = 0x01'u8
proc encode_length*(length: int): string =
  if length < 128: result = $char(length)
  elif length < 256: result = "\x81" & $char(length)
  else:
    result = "\x82" & $char(length shr 8) & $char(length and 0xFF)
proc encode_ber*(tag: BerTag, data: string): string =
  $char(tag) & encode_length(data.len) & data
proc encode_integer*(v: int): string =
  if v >= 0 and v < 128: encode_ber(tagInteger, $char(v))
  else: encode_ber(tagInteger, $char((v shr 8) and 0xFF) & $char(v and 0xFF))
proc encode_string*(s: string): string =
  encode_ber(tagOctetString, s)
proc encode_sequence*(items: seq[string]): string =
  var body = ""
  for item in items: body.add(item)
  encode_ber(tagSequence, body)
proc decode_length*(buf: string, pos: var int): int {.raises: [BridgeError].} =
  if pos >= buf.len: raise newException(BridgeError, "ber: unexpected end")
  let first = uint8(buf[pos]); inc pos
  if first < 128: return int(first)
  let num_bytes = int(first and 0x7F)
  result = 0
  for i in 0 ..< num_bytes:
    if pos >= buf.len: raise newException(BridgeError, "ber: unexpected end")
    result = (result shl 8) or int(uint8(buf[pos])); inc pos
proc decode_ber*(buf: string, pos: var int): BerValue {.raises: [BridgeError].} =
  if pos >= buf.len: raise newException(BridgeError, "ber: unexpected end")
  let tag = uint8(buf[pos]); inc pos
  let length = decode_length(buf, pos)
  if pos + length > buf.len: raise newException(BridgeError, "ber: data too short")
  let data = buf[pos ..< pos + length]; pos += length
  BerValue(tag: tag, data: data)
