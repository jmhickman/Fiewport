module Fiewport.LdapWire

open System
open System.IO
open System.Text

open Types


///
/// Encode a BER length field (short and long form).
let internal encodeBerLength (len: int) : byte array =
    match len with
    | n when n < 0x80 -> [| uint8 n |]
    | n when n < 0x100 -> [| 0x81uy; uint8 n |]
    | n when n < 0x10000 -> [| 0x82uy; uint8 (n >>> 8); uint8 n |]
    | n -> [| 0x83uy; uint8 (n >>> 16); uint8 (n >>> 8); uint8 n |]


///
/// Encode a BER TLV for a primitive or constructed value.
let internal encodeBerPrimitive (tagByte: byte) (value: byte array) : byte array =
    Array.concat [ [| tagByte |]; encodeBerLength value.Length; value ]


///
/// Encode a BER SEQUENCE containing child bytes.
let internal encodeBerSequence (content: byte array) : byte array =
    encodeBerPrimitive 0x30uy content


///
/// Four-byte big-endian view of a signed int32 (two's complement).
let private int32ToBigEndianBytes (value: int32) : byte array =
    [| uint8 (value >>> 24); uint8 (value >>> 16); uint8 (value >>> 8); uint8 value |]


///
/// Trim leading 0x00 bytes from a positive INTEGER payload; keep sign bit clear.
let private positiveIntegerContent (bytes: byte array) : byte array =
    let trimmed =
        bytes
        |> Array.skipWhile (fun b -> b = 0uy)
        |> fun arr ->
            match Array.isEmpty arr with
            | true -> [| 0uy |]
            | false -> arr
    match trimmed[0] &&& 0x80uy <> 0uy with
    | true -> Array.concat [ [| 0uy |]; trimmed ]
    | false -> trimmed


///
/// Trim leading 0xFF bytes from a negative INTEGER payload.
let private negativeIntegerContent (bytes: byte array) : byte array =
    bytes
    |> Array.skipWhile (fun b -> b = 0xFFuy)
    |> fun arr ->
        match Array.isEmpty arr with
        | true -> [| 0xFFuy |]
        | false -> arr


///
/// BER INTEGER content bytes for a signed int32.
let private integerContentBytes (value: int32) : byte array =
    let bytes = int32ToBigEndianBytes value
    match value with
    | 0 -> [| 0uy |]
    | v when v > 0 -> positiveIntegerContent bytes
    | _ -> negativeIntegerContent bytes


///
/// Encode an INTEGER value as BER.
let internal encodeBerInteger (value: int32) : byte array =
    encodeBerPrimitive 0x02uy (integerContentBytes value)


///
/// Encode an OCTET STRING.
let internal encodeBerOctetString (value: byte array) : byte array =
    encodeBerPrimitive 0x04uy value


///
/// BOOLEAN content byte (BER uses 0xFF for true).
let private booleanContentByte (value: bool) : byte =
    match value with
    | true -> 0xFFuy
    | false -> 0x00uy


///
/// Encode a BOOLEAN.
let internal encodeBerBoolean (value: bool) : byte array =
    encodeBerPrimitive 0x01uy [| booleanContentByte value |]


///
/// Encode an ENUMERATED (same payload encoding as INTEGER, tag 0x0A).
let internal encodeBerEnumerated (value: int32) : byte array =
    let asInt = encodeBerInteger value
    Array.concat [ [| 0x0Auy |]; Array.sub asInt 1 (asInt.Length - 1) ]


///
/// Accumulate big-endian length bytes starting at offset.
let private accumulateLengthBytes (input: byte array) (offset: int) (numBytes: int) : int =
    { 0 .. numBytes - 1 }
    |> Seq.fold (fun acc i -> (acc <<< 8) ||| int input[offset + 1 + i]) 0


///
/// Parse a long-form BER length (first length octet has high bit set).
let private parseLongBerLength (input: byte array) (offset: int) : int * int =
    let numBytes = int (input[offset] &&& 0x7Fuy)
    accumulateLengthBytes input offset numBytes, offset + 1 + numBytes


///
/// Parse a BER length field starting at offset. Returns (length, valueStart).
let private parseBerLength (input: byte array) (offset: int) : int * int =
    match input[offset] &&& 0x80uy = 0uy with
    | true -> int input[offset], offset + 1
    | false -> parseLongBerLength input offset


///
/// Advance past a high-tag-number BER tag (subsequent octets with high bit set).
let rec private advanceHighTagBytes (input: byte array) (i: int) : int =
    match input[i] &&& 0x80uy <> 0uy with
    | true -> advanceHighTagBytes input (i + 1)
    | false -> i + 1


///
/// End offset of the tag field starting at offset.
let private tagEndOffset (input: byte array) (offset: int) : int =
    match input[offset] &&& 0x1Fuy = 0x1Fuy with
    | true -> advanceHighTagBytes input (offset + 1)
    | false -> offset + 1


///
/// Parse a BER TLV starting at offset. Returns (valueBytes, nextOffset).
let internal parseBerTlv (input: byte array) (offset: int) : byte array * int =
    let tagEnd = tagEndOffset input offset
    let length, valueStart = parseBerLength input tagEnd
    Array.sub input valueStart length, valueStart + length


///
/// Bounds-checked TLV parse used by Result-based decoders.
let private parseBerTlvResult (input: byte array) (offset: int) : Result<byte array * int, LdapWireError> =
    try
        Ok (parseBerTlv input offset)
    with
    | ex -> Error (BerDecodeError ex.Message)


///
/// Extract the value portion of a full TLV (tag + length + value).
let private tlvValue (tlv: byte array) : byte array =
    let value, _ = parseBerTlv tlv 0
    value


///
/// Extract TLV value as Result (malformed TLV → BerDecodeError).
let private tlvValueResult (tlv: byte array) : Result<byte array, LdapWireError> =
    match parseBerTlvResult tlv 0 with
    | Error e -> Error e
    | Ok (value, _) -> Ok value


///
/// Parse one TLV at offset and cons the full TLV bytes onto the accumulator.
let private consTlvAt (content: byte array) (offset: int) (acc: byte array list) : Result<int * byte array list, LdapWireError> =
    match parseBerTlvResult content offset with
    | Error e -> Error e
    | Ok (_, next) ->
        let tlv = Array.sub content offset (next - offset)
        Ok (next, tlv :: acc)


///
/// Parse consecutive TLVs from raw content bytes. Returns full TLVs.
/// Malformed BER yields BerDecodeError (exception boundary is parseBerTlvResult only).
let private parseTlvs (content: byte array) : Result<byte array list, LdapWireError> =
    let rec loop offset acc =
        match offset >= content.Length with
        | true -> Ok (List.rev acc)
        | false ->
            match consTlvAt content offset acc with
            | Error e -> Error e
            | Ok (next, newAcc) -> loop next newAcc
    loop 0 []


///
/// True when the leading tag is SEQUENCE or SET.
let private isSequenceOrSetTag (input: byte array) : bool =
    input.Length > 0 && (input[0] = 0x30uy || input[0] = 0x31uy)


///
/// Parse all child TLVs inside a SEQUENCE-like structure.
/// - If input starts with SEQUENCE (0x30) or SET (0x31), strip that wrapper first.
/// - Otherwise parse TLVs from the raw input.
let internal parseBerSequence (input: byte array) : Result<byte array list, LdapWireError> =
    match input.Length with
    | 0 -> Ok []
    | _ when isSequenceOrSetTag input -> parseTlvs (tlvValue input)
    | _ -> parseTlvs input


///
/// Fold big-endian content bytes into a 32-bit pattern (not yet sign-extended).
let private foldBigEndianInt (valueBytes: byte array) : int =
    valueBytes |> Array.fold (fun acc b -> (acc <<< 8) ||| int b) 0


///
/// Sign-extend a short two's-complement INTEGER payload to 32 bits.
let private signExtendInteger (valueBytes: byte array) (value: int) : int =
    match valueBytes[0] &&& 0x80uy <> 0uy && valueBytes.Length < 4 with
    | false -> value
    | true ->
        let shift = (4 - valueBytes.Length) * 8
        value ||| (~~~0 <<< (32 - shift))


///
/// Decode INTEGER content bytes (length already validated).
let private integerFromContentBytes (valueBytes: byte array) : int32 =
    foldBigEndianInt valueBytes
    |> signExtendInteger valueBytes
    |> int32


///
/// Validate INTEGER content length and decode.
let private parseIntegerValueBytes (valueBytes: byte array) : Result<int32, LdapWireError> =
    match valueBytes.Length with
    | 0 -> Error (BerDecodeError "INTEGER has no value bytes")
    | n when n > 4 -> Error (BerDecodeError $"INTEGER too large: {n} bytes")
    | _ -> Ok (integerFromContentBytes valueBytes)


///
/// Parse an INTEGER value from a full BER TLV (tag + length + value).
let internal parseBerIntegerBytes (input: byte array) : Result<int32, LdapWireError> =
    match tlvValueResult input with
    | Error e -> Error e
    | Ok valueBytes -> parseIntegerValueBytes valueBytes


///
/// Parse a SEQUENCE of TLVs and return them as a list of full TLV byte arrays.
let parseSequenceFields (input: byte array) : Result<byte array list, LdapWireError> =
    parseBerSequence input


///
/// Parse an OCTET STRING value from a full TLV.
let parseOctetStringContent (input: byte array) : Result<byte array, LdapWireError> =
    tlvValueResult input


///
/// Identity framing helper kept for call-site compatibility.
/// LDAP/TCP carries a bare BER LDAPMessage SEQUENCE — NOT a 4-byte length prefix.
let internal encodeLdapMessage (berPdu: byte array) : byte array =
    berPdu


///
/// Fill buffer from stream until n bytes are read (or fail).
let rec private fillBuffer (stream: Stream) (buffer: byte array) (offset: int) (n: int) : Result<byte array, LdapWireError> =
    match offset >= n with
    | true -> Ok buffer
    | false ->
        match stream.Read(buffer, offset, n - offset) with
        | 0 -> Error (ConnectionFailed "LDAP stream closed unexpectedly")
        | read -> fillBuffer stream buffer (offset + read) n


///
/// Read exactly n bytes from a stream.
let private readExactly (stream: Stream) (n: int) : Result<byte array, LdapWireError> =
    fillBuffer stream (Array.zeroCreate n) 0 n


///
/// Read a single stream byte as Result.
let private readStreamByte (stream: Stream) (context: string) : Result<int, LdapWireError> =
    match stream.ReadByte() with
    | b when b < 0 -> Error (ConnectionFailed $"LDAP stream closed while reading {context}")
    | b -> Ok b


///
/// Fold long-form length content bytes into an integer length.
let private foldLengthContent (lenBytes: byte array) : int =
    lenBytes |> Array.fold (fun acc b -> (acc <<< 8) ||| int b) 0


///
/// Parse long-form BER length from the stream after the first length octet.
let private readLongBerLength (stream: Stream) (lenFirst: int) : Result<byte array * int, LdapWireError> =
    let num = lenFirst &&& 0x7F
    match num <= 0 || num > 4 with
    | true -> Error (ConnectionFailed $"Invalid BER length octet count: {num}")
    | false ->
        match readExactly stream num with
        | Error e -> Error e
        | Ok lenBytes ->
            Ok (Array.concat [| [| byte lenFirst |]; lenBytes |], foldLengthContent lenBytes)


///
/// Parse BER length prefix from stream; returns (lengthPrefixBytes, contentLength).
let private readBerLengthPrefix (stream: Stream) (lenFirst: int) : Result<byte array * int, LdapWireError> =
    match lenFirst &&& 0x80 = 0 with
    | true -> Ok ([| byte lenFirst |], lenFirst)
    | false -> readLongBerLength stream lenFirst


///
/// Assemble tag + length prefix + content into one TLV buffer.
let private assembleBerTlv (tag: int) (lengthPrefix: byte array) (content: byte array) : byte array =
    Array.concat [| [| byte tag |]; lengthPrefix; content |]


///
/// Read content bytes after a validated non-negative length.
let private readBerContent (stream: Stream) (tag: int) (lengthPrefix: byte array) (contentLen: int) : Result<byte array, LdapWireError> =
    match contentLen < 0 with
    | true -> Error (ConnectionFailed "Negative BER content length")
    | false ->
        match readExactly stream contentLen with
        | Error e -> Error e
        | Ok content -> Ok (assembleBerTlv tag lengthPrefix content)


///
/// Continue readBerTlv after tag and first length octet are known.
let private readBerTlvAfterTag (stream: Stream) (tag: int) (lenFirst: int) : Result<byte array, LdapWireError> =
    match readBerLengthPrefix stream lenFirst with
    | Error e -> Error e
    | Ok (lengthPrefix, contentLen) -> readBerContent stream tag lengthPrefix contentLen


///
/// Read one complete BER TLV from the stream (tag + length + content).
let private readBerTlv (stream: Stream) : Result<byte array, LdapWireError> =
    match readStreamByte stream "tag" with
    | Error e -> Error e
    | Ok tag ->
        match readStreamByte stream "length" with
        | Error e -> Error e
        | Ok lenFirst -> readBerTlvAfterTag stream tag lenFirst


///
/// Send a complete LDAP message over the stream.
/// berContent is the protocolOp TLV (e.g. SearchRequest APPLICATION 3).
let internal sendMessage (stream: Stream) (messageId: int32) (berContent: byte array) : unit =
    let pdu =
        Array.concat [ encodeBerInteger messageId; berContent ]
        |> encodeBerSequence
    stream.Write(pdu, 0, pdu.Length)
    stream.Flush()


///
/// Optional controls TLV: first [0] context-specific among trailing fields.
let private findControlsTlv (trailing: byte array list) : byte array option =
    trailing |> List.tryFind (fun t -> t.Length > 0 && t[0] = 0xA0uy)


///
/// Classify protocolOp tag into LdapMessage.
let private classifyProtocolOp (pduField: byte array) (controls: byte array option) : LdapMessage =
    match pduField[0] with
    | 0x64uy -> SearchResultEntry pduField
    | 0x65uy -> SearchResultDone (pduField, controls)
    | 0x73uy -> SearchReference pduField
    | tag -> OtherProtocolOp (tag, pduField)


///
/// Build LdapMessage from protocolOp + trailing control fields.
let private messageFromPduAndTrailing (pduField: byte array) (trailing: byte array list) : LdapMessage =
    classifyProtocolOp pduField (findControlsTlv trailing)


///
/// Decode fields after message id INTEGER.
let private decodeMessageAfterMsgId (rest: byte array list) : Result<LdapMessage, LdapWireError> =
    match rest with
    | [] -> Error (BerDecodeError "No PDU in LDAP message")
    | pduField :: trailing -> Ok (messageFromPduAndTrailing pduField trailing)


///
/// Decode LDAPMessage fields after successful SEQUENCE parse.
let private decodeLdapMessageFields (fields: byte array list) : Result<LdapMessage, LdapWireError> =
    match fields with
    | [] -> Error (BerDecodeError "Empty LDAP message")
    | msgIdField :: rest ->
        match parseBerIntegerBytes msgIdField with
        | Error e -> Error e
        | Ok _ -> decodeMessageAfterMsgId rest


///
/// Parse a complete LDAPMessage SEQUENCE payload into LdapMessage.
let private decodeLdapMessagePayload (payload: byte array) : Result<LdapMessage, LdapWireError> =
    match parseBerSequence payload with
    | Error e -> Error e
    | Ok fields -> decodeLdapMessageFields fields


///
/// Map stream/decode failures that escape as exceptions (timeouts, etc.).
let private mapReceiveException (ex: exn) : LdapWireError =
    match ex with
    | :? TimeoutException -> Timeout "Read timeout on LDAP stream"
    | :? IOException as ioEx -> ConnectionFailed ioEx.Message
    | _ -> Unexpected ex.Message


///
/// Receive one LDAP message from the stream (one BER LDAPMessage).
let internal receiveMessage (stream: Stream) : Result<LdapMessage, LdapWireError> =
    try
        match readBerTlv stream with
        | Error e -> Error e
        | Ok payload -> decodeLdapMessagePayload payload
    with
    | ex -> Error (mapReceiveException ex)


/// Attribute description / assertion value as UTF-8 OCTET STRING.
let private encodeLdapString (s: string) : byte array =
    encodeBerOctetString (Encoding.UTF8.GetBytes s)


///
/// Equality match filter: [3] IMPLICIT AttributeValueAssertion.
let private encodeEqualityFilter (attr: string) (value: string) : byte array =
    encodeBerPrimitive 0xA3uy (Array.concat [| encodeLdapString attr; encodeLdapString value |])


///
/// Present filter: [7] IMPLICIT AttributeDescription.
let private encodePresentFilter (attr: string) : byte array =
    encodeBerPrimitive 0x87uy (Encoding.UTF8.GetBytes attr)


///
/// Substring component tag: initial [0], any [1], final [2].
let private substringComponentTag (index: int) (last: int) : byte =
    match index with
    | 0 -> 0x80uy
    | i when i = last -> 0x82uy
    | _ -> 0x81uy


///
/// Encode one non-empty substring piece; empty pieces are omitted.
let private encodeSubstringPiece (last: int) (index: int) (piece: string) : byte array =
    match piece.Length with
    | 0 -> [||]
    | _ -> encodeBerPrimitive (substringComponentTag index last) (Encoding.UTF8.GetBytes piece)


///
/// Substring filter: [4] IMPLICIT SubstringFilter.
let private encodeSubstringFilter (attr: string) (raw: string) : byte array =
    let parts = raw.Split([| '*' |], StringSplitOptions.None)
    let last = parts.Length - 1
    let components =
        parts
        |> Array.mapi (encodeSubstringPiece last)
        |> Array.concat
    let body = Array.concat [| encodeLdapString attr; components |]
    encodeBerPrimitive 0xA4uy body


///
/// Extensible match: [9] IMPLICIT MatchingRuleAssertion
let private encodeExtensibleFilter (attr: string) (rule: string) (value: string) : byte array =
    let body =
        Array.concat
            [| encodeBerPrimitive 0x81uy (Encoding.UTF8.GetBytes rule)
               encodeBerPrimitive 0x82uy (Encoding.UTF8.GetBytes attr)
               encodeBerPrimitive 0x83uy (Encoding.UTF8.GetBytes value) |]
    encodeBerPrimitive 0xA9uy body


///
/// Try to consume a \\HH hex escape at index i; return new index and updated acc.
let private tryConsumeHexEscape (s: string) (i: int) (acc: char list) : int * char list =
    let hex = s.Substring(i + 1, 2)
    match Byte.TryParse(hex, Globalization.NumberStyles.HexNumber, null) with
    | true, b -> i + 3, char b :: acc
    | _ -> i + 1, s[i] :: acc


///
/// Step unescape at index i.
let private unescapeStep (s: string) (i: int) (acc: char list) : int * char list =
    match s[i] = '\\' && i + 2 < s.Length with
    | true -> tryConsumeHexEscape s i acc
    | false -> i + 1, s[i] :: acc


///
/// Recursive unescape of RFC 4515 hex escapes (\\HH).
let rec private unescapeLoop (s: string) (i: int) (acc: char list) : string =
    match i >= s.Length with
    | true ->
        acc
        |> List.rev
        |> Array.ofList
        |> String
    | false ->
        let nextI, nextAcc = unescapeStep s i acc
        unescapeLoop s nextI nextAcc


///
/// Unescape RFC 4515 hex escapes in an assertion value (\\HH).
let private unescapeAssertionValue (s: string) : string =
    unescapeLoop s 0 []


///
/// Mutual recursion: filter string ↔ body ↔ set/item/extract.
let rec private encodeFilterBody (body: string) : Result<byte array, LdapWireError> =
    match body.Trim() with
    | b when b.Length = 0 -> Error (BerDecodeError "Empty LDAP filter body")
    | b ->
        match b[0] with
        | '&' -> encodeSetFilter 0xA0uy (b.Substring(1))
        | '|' -> encodeSetFilter 0xA1uy (b.Substring(1))
        | '!' -> encodeNotFilter (b.Substring(1))
        | _ -> encodeItemFilter b

and private encodeNotFilter (rest: string) : Result<byte array, LdapWireError> =
    match extractNextFilter (rest.TrimStart()) with
    | Error e -> Error e
    | Ok (child, leftover) when String.IsNullOrWhiteSpace leftover ->
        match encodeFilterString child with
        | Error e -> Error e
        | Ok childBer -> Ok (encodeBerPrimitive 0xA2uy childBer)
    | Ok _ -> Error (BerDecodeError $"Trailing junk in NOT filter: {rest}")

and private appendEncodedChild (remaining: string) (childText: string) (acc: byte array list) : Result<byte array list, LdapWireError> =
    match encodeFilterString childText with
    | Error e -> Error e
    | Ok childBer -> collectSetChildren remaining (childBer :: acc)

and private collectSetChildren (input: string) (acc: byte array list) : Result<byte array list, LdapWireError> =
    match input.TrimStart() with
    | trimmed when trimmed.Length = 0 -> Ok (List.rev acc)
    | trimmed ->
        match extractNextFilter trimmed with
        | Error e -> Error e
        | Ok (childText, remaining) -> appendEncodedChild remaining childText acc

and private encodeSetFilter (tag: byte) (rest: string) : Result<byte array, LdapWireError> =
    match collectSetChildren rest [] with
    | Error e -> Error e
    | Ok [] -> Error (BerDecodeError "AND/OR filter requires at least one child")
    | Ok children ->
        children
        |> List.toArray
        |> Array.concat
        |> encodeBerPrimitive tag
        |> Ok

and private scanFilterClose (s: string) (i: int) (depth: int) : Result<int, LdapWireError> =
    match i >= s.Length with
    | true -> Error (BerDecodeError $"Unbalanced parentheses in filter: {s}")
    | false ->
        match s[i] with
        | '(' -> scanFilterClose s (i + 1) (depth + 1)
        | ')' ->
            match depth - 1 with
            | 0 -> Ok i
            | d -> scanFilterClose s (i + 1) d
        | '\\' when i + 1 < s.Length -> scanFilterClose s (i + 2) depth
        | _ -> scanFilterClose s (i + 1) depth

and private splitAtMatchingParen (s: string) : Result<string * string, LdapWireError> =
    match scanFilterClose s 0 0 with
    | Error e -> Error e
    | Ok closeIdx -> Ok (s.Substring(0, closeIdx + 1), s.Substring(closeIdx + 1))

and private extractNextFilter (input: string) : Result<string * string, LdapWireError> =
    match input.TrimStart() with
    | s when s.Length = 0 || s[0] <> '(' ->
        Error (BerDecodeError $"Expected '(' in filter, got: {input}")
    | s -> splitAtMatchingParen s

and private encodeExtensibleFromParts (body: string) (parts: string array) (value: string) : Result<byte array, LdapWireError> =
    match parts with
    | [| attr; rule |] -> Ok (encodeExtensibleFilter attr rule value)
    | [| attr; _; rule |] -> Ok (encodeExtensibleFilter attr rule value)
    | _ -> Error (BerDecodeError $"Unsupported extensible filter: {body}")

and private encodeExtensibleItem (body: string) (extIdx: int) : Result<byte array, LdapWireError> =
    let left = body.Substring(0, extIdx)
    let value = unescapeAssertionValue (body.Substring(extIdx + 2))
    encodeExtensibleFromParts body (left.Split(':')) value

and private encodePresentSubstringOrEquality (attr: string) (value: string) : Result<byte array, LdapWireError> =
    match value with
    | "*" -> Ok (encodePresentFilter attr)
    | v when v.Contains("*") -> Ok (encodeSubstringFilter attr v)
    | v -> Ok (encodeEqualityFilter attr v)

and private encodeEqualityItem (body: string) : Result<byte array, LdapWireError> =
    match body.IndexOf '=' with
    | eqIdx when eqIdx <= 0 -> Error (BerDecodeError $"Invalid item filter (no '='): {body}")
    | eqIdx ->
        let attr = body.Substring(0, eqIdx)
        let value = unescapeAssertionValue (body.Substring(eqIdx + 1))
        encodePresentSubstringOrEquality attr value

and private encodeItemFilter (body: string) : Result<byte array, LdapWireError> =
    match body.IndexOf(":=") with
    | extIdx when extIdx > 0 -> encodeExtensibleItem body extIdx
    | _ -> encodeEqualityItem body

and private encodeParenthesizedFilter (f: string) : Result<byte array, LdapWireError> =
    match extractNextFilter f with
    | Error e -> Error e
    | Ok (filterText, remaining) when String.IsNullOrWhiteSpace remaining ->
        encodeFilterBody (filterText.Substring(1, filterText.Length - 2))
    | Ok (_, remaining) ->
        Error (BerDecodeError $"Trailing junk after filter: {remaining}")

and private encodeFilterString (filter: string) : Result<byte array, LdapWireError> =
    match filter.Trim() with
    | f when f.Length = 0 -> Ok (encodePresentFilter "objectClass")
    | f when f[0] = '(' -> encodeParenthesizedFilter f
    | f -> encodeFilterBody f


let internal encodeFilter (filter: string) : Result<byte array, LdapWireError> =
    encodeFilterString filter


///
/// Build a complete LDAPMessage containing a SearchRequest.
let internal encodeSearchRequest (request: SearchRequestToEncode) : byte array =

    let filterBytes =
        match encodeFilter request.searchFilter with
        | Ok b -> b
        | Error _ ->
            encodePresentFilter "objectClass"

    let attrBytes =
        request.attributeNames
        |> Array.map encodeLdapString
        |> Array.concat
        |> encodeBerSequence

    let searchContent =
        Array.concat
            [ encodeLdapString request.baseObject
              encodeBerEnumerated (int32 request.searchScopeByte)
              encodeBerEnumerated (int32 request.derefAliases)
              encodeBerInteger request.sizeLimit
              encodeBerInteger request.timeLimit
              encodeBerBoolean request.typesOnly
              filterBytes
              attrBytes ]

    let searchRequest = encodeBerPrimitive 0x63uy searchContent

    Array.concat [ encodeBerInteger request.messageId; searchRequest ]
    |> encodeBerSequence


///
/// Build one LDAP Control SEQUENCE { OID, criticality?, controlValue OCTET STRING }.
let private encodeControl (oid: string) (critical: bool) (value: byte array option) : byte array =
    let oidTlv = encodeLdapString oid
    let critTlv =
        if critical then encodeBerBoolean true
        else [||]
    let valueTlv =
        match value with
        | Some v -> encodeBerOctetString v
        | None -> [||]
    Array.concat [| oidTlv; critTlv; valueTlv |]
    |> encodeBerSequence


///
/// SD Flags control (1.2.840.113556.1.4.801).
/// controlValue BER: SEQUENCE { INTEGER flags } where 7 = OWNER|GROUP|DACL.
/// 
let internal encodeSdFlagsControl : byte array =
    let flagsValue =
        encodeBerSequence (encodeBerInteger 7)
    encodeControl "1.2.840.113556.1.4.801" false (Some flagsValue)


///
/// Simple Paged Results control (1.2.840.113556.1.4.319 / RFC 2696).
let internal encodePagedResultsControl (pageSize: int32) (cookie: byte array option) : byte array =
    let cookieBytes =
        match cookie with
        | Some c -> c
        | None -> [||]
    let realValue =
        Array.concat [ encodeBerInteger pageSize; encodeBerOctetString cookieBytes ]
        |> encodeBerSequence
    encodeControl "1.2.840.113556.1.4.319" false (Some realValue)


///
/// Optional controls TLV among LDAPMessage trailing fields.
let private controlsFromTrailing (rest: byte array list) : byte array option =
    rest |> List.tryFind (fun t -> t.Length > 0 && t[0] = 0xA0uy)


///
/// LDAPMessage fields starting with message id INTEGER + protocolOp.
let private splitMessageWithMsgId (msgIdTlv: byte array) (pdu: byte array) (rest: byte array list) : Result<int32 option * byte array * byte array option, LdapWireError> =
    match parseBerIntegerBytes msgIdTlv with
    | Error e -> Error e
    | Ok mid -> Ok (Some mid, pdu, controlsFromTrailing rest)


///
/// Classify parsed LDAPMessage SEQUENCE children.
let private splitLdapMessageFields (fields: byte array list) : Result<int32 option * byte array * byte array option, LdapWireError> =
    match fields with
    | [] -> Error (BerDecodeError "Empty LDAPMessage")
    | msgIdTlv :: pdu :: rest when msgIdTlv.Length > 0 && msgIdTlv[0] = 0x02uy ->
        splitMessageWithMsgId msgIdTlv pdu rest
    | pdu :: _ -> Ok (None, pdu, None)


///
/// Input is a full LDAPMessage SEQUENCE — unwrap and classify children.
let private splitLdapMessageSequence (input: byte array) : Result<int32 option * byte array * byte array option, LdapWireError> =
    match parseBerSequence input with
    | Error e -> Error e
    | Ok fields -> splitLdapMessageFields fields


///
/// If input is a full LDAPMessage SEQUENCE, return (msgId option, protocolOp TLV, controls option).
/// If input is already a protocolOp TLV, return (None, input, None).
let private splitMessageOrPdu (input: byte array) : Result<int32 option * byte array * byte array option, LdapWireError> =
    match input with
    | [||] -> Error (BerDecodeError "Empty PDU")
    | bytes when bytes[0] = 0x30uy -> splitLdapMessageSequence bytes
    | bytes -> Ok (None, bytes, None)


///
/// Continue the railway after a successful or failed splitMessageOrPdu.
let private continueAfterSplit (parseSplit: WireSplit -> Result<'a, LdapWireError>) (splitResult: Result<WireSplit, LdapWireError>) : Result<'a, LdapWireError> =
    match splitResult with
    | Error e -> Error e
    | Ok parts -> parseSplit parts


///
/// Default exception map for wire PDU decoders (BER/structural failures).
let private mapBerDecodeException (ex: exn) : LdapWireError =
    BerDecodeError ex.Message


///
/// Shared entry: split LDAPMessage-or-bare-PDU, then parse the protocolOp (ROP).
let private parseWirePdu (parseSplit: WireSplit -> Result<'a, LdapWireError>) (mapEx: exn -> LdapWireError) (pdu: byte array) : Result<'a, LdapWireError> =
    try
        pdu
        |> splitMessageOrPdu
        |> continueAfterSplit parseSplit
    with
    | ex -> Error (mapEx ex)


///
/// Decode attribute description OCTET STRING to lowercase name.
let private attributeNameFromTlv (nameTlv: byte array) : string =
    tlvValue nameTlv
    |> Encoding.UTF8.GetString
    |> fun s -> s.ToLowerInvariant()


///
/// Decode SET OF value TLVs into raw byte values (empty on malformed SET).
let private attributeValuesFromSetTlv (valuesSetTlv: byte array) : byte array list =
    match parseBerSequence valuesSetTlv with
    | Error _ -> []
    | Ok valueTlvs -> valueTlvs |> List.map tlvValue


///
/// Parse one Attribute SEQUENCE TLV into (lowercase name, values).
let private parseAttribute (attrTlv: byte array) : (string * byte array list) option =
    match parseBerSequence attrTlv with
    | Error _ -> None
    | Ok [ nameTlv; valuesSetTlv ] ->
        Some (attributeNameFromTlv nameTlv, attributeValuesFromSetTlv valuesSetTlv)
    | Ok _ -> None


///
/// True when the TLV is SearchResultEntry (APPLICATION 4).
let private isSearchResultEntryTlv (entryTlv: byte array) : bool =
    entryTlv.Length > 0 && entryTlv[0] = 0x64uy


///
/// Decode DN OCTET STRING as UTF-8.
let private dnFromTlv (dnTlv: byte array) : string =
    tlvValue dnTlv |> Encoding.UTF8.GetString


///
/// Build attribute map from Attribute SEQUENCE TLVs.
let private attributeMapFromTlvs (attrTlvs: byte array list) : Map<string, byte array list> =
    attrTlvs
    |> List.choose parseAttribute
    |> Map.ofList


///
/// Decode attrs SEQUENCE TLV into the entry attribute map.
let private parseEntryAttributes (attrsTlv: byte array) : Result<Map<string, byte array list>, LdapWireError> =
    match parseBerSequence attrsTlv with
    | Error e -> Error e
    | Ok attrTlvs -> Ok (attributeMapFromTlvs attrTlvs)


///
/// Build RawLdapEntry from DN TLV + attrs TLV.
let private buildRawLdapEntry (dnTlv: byte array) (attrsTlv: byte array) : Result<RawLdapEntry, LdapWireError> =
    match parseEntryAttributes attrsTlv with
    | Error e -> Error e
    | Ok attributes ->
        Ok
            { DN = dnFromTlv dnTlv
              Attributes = attributes }


///
/// Interpret APPLICATION 4 value fields: SEQUENCE { DN, PartialAttributeList }.
let private parseSearchResultEntryFields (fields: byte array list) : Result<RawLdapEntry, LdapWireError> =
    match fields with
    | [ dnTlv; attrsTlv ] -> buildRawLdapEntry dnTlv attrsTlv
    | _ -> Error (BerDecodeError "Invalid SearchResultEntry structure")


///
/// Decode the value bytes of an APPLICATION 4 TLV.
let private parseEntryTlvValue (entryTlv: byte array) : Result<RawLdapEntry, LdapWireError> =
    match parseTlvs (tlvValue entryTlv) with
    | Error e -> Error e
    | Ok fields -> parseSearchResultEntryFields fields


///
/// Parse a SearchResultEntry protocolOp TLV (tag-checked).
let private parseSearchResultEntryTlv (entryTlv: byte array) : Result<RawLdapEntry, LdapWireError> =
    match isSearchResultEntryTlv entryTlv with
    | false -> Error (BerDecodeError "Expected SearchResultEntry APPLICATION 4")
    | true -> parseEntryTlvValue entryTlv


///
/// Map entry-decode exceptions (bad UTF-8, truncated TLV) to BerDecodeError.
let private mapEntryDecodeException (ex: exn) : LdapWireError =
    match ex with
    | :? ArgumentException -> BerDecodeError "Invalid UTF-8 in DN"
    | _ -> BerDecodeError ex.Message


///
/// Continue split railway into SearchResultEntry protocolOp parse.
let private parseEntryFromSplit ((_msgId, entryTlv, _controls): WireSplit) : Result<RawLdapEntry, LdapWireError> =
    parseSearchResultEntryTlv entryTlv


///
/// Parse a SearchResultEntry (full LDAPMessage OR bare APPLICATION 4 TLV).
let internal parseSearchResultEntry (pdu: byte array) : Result<RawLdapEntry, LdapWireError> =
    parseWirePdu parseEntryFromSplit mapEntryDecodeException pdu


///
/// Extract URI strings from an LDAPResult referral [3] TLV (CONTEXT 0xA3).
let private referralUrisFromTlv (referralTlv: byte array) : string list =
    match parseTlvs (tlvValue referralTlv) with
    | Error _ -> []
    | Ok uriTlvs ->
        uriTlvs
        |> List.map (fun tlv -> tlvValue tlv |> Encoding.UTF8.GetString)


///
/// Pull optional referral URIs from LDAPResult fields after resultCode.
let private extractLdapResultReferrals (fieldsAfterCode: byte array list) : string list =
    fieldsAfterCode
    |> List.tryFind (fun tlv -> tlv.Length > 0 && tlv[0] = 0xA3uy)
    |> Option.map referralUrisFromTlv
    |> Option.defaultValue []


///
/// True when the TLV is SearchResultDone (APPLICATION 5).
let private isSearchResultDoneTlv (doneTlv: byte array) : bool =
    doneTlv.Length > 0 && doneTlv[0] = 0x65uy


///
/// ENUMERATED resultCode shares INTEGER encoding; retag 0x0A as 0x02 for the integer parser.
let private retagEnumeratedAsInteger (resultCodeTlv: byte array) : byte array =
    match resultCodeTlv.Length > 0 && resultCodeTlv[0] = 0x0Auy with
    | true -> Array.concat [| [| 0x02uy |]; Array.sub resultCodeTlv 1 (resultCodeTlv.Length - 1) |]
    | false -> resultCodeTlv


///
/// Decode the LDAPResult resultCode INTEGER/ENUMERATED TLV.
let private parseResultCodeInteger (resultCodeTlv: byte array) : Result<int32, LdapWireError> =
    resultCodeTlv
    |> retagEnumeratedAsInteger
    |> parseBerIntegerBytes


///
/// Build the Done triple once the resultCode TLV is known.
let private decodeSearchResultDoneBody (msgIdOpt: int32 option) (resultCodeTlv: byte array) (rest: byte array list) : Result<int32 * SearchResultStatus * string list, LdapWireError> =
    match parseResultCodeInteger resultCodeTlv with
    | Error e -> Error e
    | Ok code ->
        Ok (defaultArg msgIdOpt 0, SearchResultStatus.FromCode code, extractLdapResultReferrals rest)


///
/// Interpret APPLICATION 5 value fields as LDAPResult.
let private parseSearchResultDoneFields (msgIdOpt: int32 option) (fields: byte array list) : Result<int32 * SearchResultStatus * string list, LdapWireError> =
    match fields with
    | [] -> Error (BerDecodeError "Empty SearchResultDone")
    | resultCodeTlv :: rest -> decodeSearchResultDoneBody msgIdOpt resultCodeTlv rest


///
/// Decode the value bytes of an APPLICATION 5 TLV.
let private parseDoneTlvValue (msgIdOpt: int32 option) (doneTlv: byte array) : Result<int32 * SearchResultStatus * string list, LdapWireError> =
    match parseTlvs (tlvValue doneTlv) with
    | Error e -> Error e
    | Ok fields -> parseSearchResultDoneFields msgIdOpt fields


///
/// Parse a verified-or-not SearchResultDone protocolOp TLV.
let private parseSearchResultDoneTlv (msgIdOpt: int32 option) (doneTlv: byte array) : Result<int32 * SearchResultStatus * string list, LdapWireError> =
    match isSearchResultDoneTlv doneTlv with
    | false -> Error (BerDecodeError "Expected SearchResultDone APPLICATION 5")
    | true -> parseDoneTlvValue msgIdOpt doneTlv


///
/// Continue split railway into SearchResultDone protocolOp parse (keeps message id).
let private parseDoneFromSplit ((msgIdOpt, doneTlv, _controls): WireSplit) : Result<int32 * SearchResultStatus * string list, LdapWireError> =
    parseSearchResultDoneTlv msgIdOpt doneTlv


///
/// Parse a SearchResultDone (full LDAPMessage OR bare APPLICATION 5 TLV).
/// Returns message id, result status, and any LDAPResult.referral URIs (RFC 4511).
let internal parseSearchResultDone (pdu: byte array) : Result<int32 * SearchResultStatus * string list, LdapWireError> =
    parseWirePdu parseDoneFromSplit mapBerDecodeException pdu


///
/// OID for Simple Paged Results (RFC 2696 / 1.2.840.113556.1.4.319).
let private pagedResultsControlOid = "1.2.840.113556.1.4.319"


///
/// True when the TLV is a BER SEQUENCE.
let private isSequenceTlv (tlv: byte array) : bool =
    tlv.Length > 0 && tlv[0] = 0x30uy


///
/// True when the TLV is an OCTET STRING.
let private isOctetStringTlv (tlv: byte array) : bool =
    tlv.Length > 0 && tlv[0] = 0x04uy


///
/// True when parsed children look like a SEQUENCE OF Control (each child a SEQUENCE).
let private childrenLookLikeControlSequences (children: byte array list) : bool =
    children |> List.exists isSequenceTlv


///
/// Unwrap a SEQUENCE-tagged controls blob into individual Control TLVs.
let private parseSequenceWrappedControls (controls: byte array) : Result<byte array list, LdapWireError> =
    match parseTlvs (tlvValue controls) with
    | Error e -> Error e
    | Ok children ->
        match childrenLookLikeControlSequences children with
        | true -> Ok children
        | false -> Ok [ controls ]


///
/// Normalize controls bytes into a list of Control SEQUENCE TLVs.
let private unwrapControlTlvs (controls: byte array) : Result<byte array list, LdapWireError> =
    match controls[0] with
    | 0xA0uy -> parseTlvs (tlvValue controls)
    | 0x30uy -> parseSequenceWrappedControls controls
    | _ -> parseTlvs controls


///
/// Empty cookie means paging is finished — surface as None.
let private nonEmptyCookie (cookie: byte array) : byte array option =
    match Array.isEmpty cookie with
    | true -> None
    | false -> Some cookie


///
/// Decode paged-results controlValue: SEQUENCE { size INTEGER, cookie OCTET STRING }.
let private cookieFromPagedValueBytes (valueBytes: byte array) : CookieSearchStep =
    match parseBerSequence valueBytes with
    | Ok fields when fields.Length >= 2 ->
        CookieFound (tlvValue (List.last fields) |> nonEmptyCookie)
    | _ -> KeepSearching


///
/// Last OCTET STRING after the control OID is the controlValue (criticality may precede it).
let private controlValueOctetString (restFields: byte array list) : byte array option =
    restFields
    |> List.tryFindBack isOctetStringTlv
    |> Option.map tlvValue


///
/// Extract cookie search step from fields following a paged-results control OID.
let private stepPagedControlFields (restFields: byte array list) : CookieSearchStep =
    match controlValueOctetString restFields with
    | None -> KeepSearching
    | Some valueBytes -> cookieFromPagedValueBytes valueBytes


///
/// Read control type OID from the first field of a Control SEQUENCE.
let private oidFromControlField (oidTlv: byte array) : string option =
    match isOctetStringTlv oidTlv with
    | false -> None
    | true -> Some (tlvValue oidTlv |> Encoding.ASCII.GetString)


///
/// Inspect one Control TLV for the paged-results cookie.
let private stepControlTlv (ctrlTlv: byte array) : CookieSearchStep =
    match parseBerSequence ctrlTlv with
    | Ok (oidTlv :: restFields) ->
        match oidFromControlField oidTlv with
        | Some oid when oid = pagedResultsControlOid -> stepPagedControlFields restFields
        | _ -> KeepSearching
    | _ -> KeepSearching


///
/// Walk Control TLVs until the paged-results cookie is resolved or the list ends.
let rec private findPagedCookie (ctrlTlvs: byte array list) : byte array option =
    match ctrlTlvs with
    | [] -> None
    | ctrlTlv :: rest ->
        match stepControlTlv ctrlTlv with
        | CookieFound result -> result
        | KeepSearching -> findPagedCookie rest


///
/// Parse controls bytes and locate the paged-results cookie.
let private readCookieFromControlBytes (controls: byte array) : byte array option =
    match unwrapControlTlvs controls with
    | Error _ -> None
    | Ok ctrlTlvs -> findPagedCookie ctrlTlvs


///
/// Extract the paged results control cookie from response controls.
/// `controlsBer` is the raw [0] context TLV from LDAPMessage (IMPLICIT SEQUENCE OF Control),
/// or the unwrapped SEQUENCE OF Control content.
/// Returns None if no paged results control found or cookie is empty.
/// 
let internal readPagedCookie (controlsBer: byte array option) : byte array option =
    match controlsBer with
    | None -> None
    | Some controls when controls.Length = 0 -> None
    | Some controls -> readCookieFromControlBytes controls


///
/// True when the TLV is SearchResultReference (APPLICATION 19).
let private isSearchResultReferenceTlv (refTlv: byte array) : bool =
    refTlv.Length > 0 && refTlv[0] = 0x73uy


///
/// Decode one referral URI OCTET STRING TLV.
let private uriStringFromTlv (tlv: byte array) : string =
    tlvValue tlv |> Encoding.UTF8.GetString


///
/// Map REFERENCE URI TLVs to strings.
let private decodeReferenceUriTlvs (uriTlvs: byte array list) : string list =
    uriTlvs |> List.map uriStringFromTlv


///
/// Parse the value of an APPLICATION 19 TLV into referral URI strings.
let private parseReferenceTlvValue (refTlv: byte array) : Result<string list, LdapWireError> =
    match parseTlvs (tlvValue refTlv) with
    | Error e -> Error e
    | Ok uriTlvs -> Ok (decodeReferenceUriTlvs uriTlvs)


///
/// Parse a SearchResultReference protocolOp TLV (tag-checked).
let private parseSearchReferenceTlv (refTlv: byte array) : Result<string list, LdapWireError> =
    match isSearchResultReferenceTlv refTlv with
    | false -> Error (BerDecodeError "Expected SearchResultReference APPLICATION 19")
    | true -> parseReferenceTlvValue refTlv


///
/// Continue split railway into SearchResultReference protocolOp parse.
let private parseReferenceFromSplit ((_msgId, refTlv, _controls): WireSplit) : Result<string list, LdapWireError> =
    parseSearchReferenceTlv refTlv


///
/// Extract referral URIs from a SearchResultReference.
/// Accepts full LDAPMessage or bare APPLICATION 19 TLV.
let internal parseSearchReference (pdu: byte array) : Result<string list, LdapWireError> =
    parseWirePdu parseReferenceFromSplit mapBerDecodeException pdu


///
/// True when the string is a literal IPv4/IPv6 address.
let internal hostLooksLikeIp (host: string) : bool =
    match System.Net.IPAddress.TryParse host with
    | true, _ -> true
    | false, _ -> false


///
/// Valid TCP port range for LDAP URLs.
let private isValidTcpPort (port: int) : bool =
    port > 0 && port <= 65535


///
/// Parse a port string; reject empty/out-of-range values.
let private parsePortString (portText: string) : Result<int, LdapWireError> =
    match Int32.TryParse portText with
    | true, p when isValidTcpPort p -> Ok p
    | _ -> Error (BerDecodeError "Invalid LDAP URL: bad port")


///
/// Optional host: empty string becomes None.
let private optionalHost (hostPart: string) : string option =
    match String.IsNullOrEmpty hostPart with
    | true -> None
    | false -> Some hostPart


///
/// Combine optional host with a successfully parsed port.
let private hostWithPort (hostPart: string) (port: int) : string option * int option =
    optionalHost hostPart, Some port


///
/// Parse a required ":port" suffix into host+port.
let private parseColonPortSuffix (hostPart: string) (after: string) : Result<string option * int option, LdapWireError> =
    match parsePortString (after.Substring(1)) with
    | Error e -> Error e
    | Ok port -> Ok (hostWithPort hostPart port)


///
/// Parse ":port" suffix after an IPv6 bracket host; empty suffix means no port.
let private parsePortSuffixAfterHost (hostPart: string) (after: string) : Result<string option * int option, LdapWireError> =
    match after with
    | "" -> Ok (Some hostPart, None)
    | _ when after.StartsWith(":", StringComparison.Ordinal) -> parseColonPortSuffix hostPart after
    | _ -> Error (BerDecodeError "Invalid LDAP URL: junk after IPv6 host")


///
/// Parse bracketed IPv6 authority: [addr] or [addr]:port.
let private parseBracketedIpv6Authority (authority: string) : Result<string option * int option, LdapWireError> =
    match authority.IndexOf(']') with
    | -1 -> Error (BerDecodeError "Invalid LDAP URL: unclosed IPv6 bracket")
    | closeIdx ->
        let hostPart = authority.Substring(1, closeIdx - 1)
        let after = authority.Substring(closeIdx + 1)
        parsePortSuffixAfterHost hostPart after


///
/// Attach a parsed port to a host part (host may be empty → None).
let private bindHostToPort (hostPart: string) (portPart: string) : Result<string option * int option, LdapWireError> =
    match parsePortString portPart with
    | Error e -> Error e
    | Ok port -> Ok (hostWithPort hostPart port)


///
/// Host:port split when the left side is not unbracketed IPv6.
let private parseSimpleHostPort (authority: string) (hostPart: string) (portPart: string) : Result<string option * int option, LdapWireError> =
    match hostPart.Contains(':') with
    | true -> Ok (Some authority, None) // bare IPv6 without brackets
    | false -> bindHostToPort hostPart portPart


///
/// Parse host:port when a colon is present (non-bracket authority).
let private parseHostPortAtColon (authority: string) (colon: int) : Result<string option * int option, LdapWireError> =
    match colon = authority.Length - 1 with
    | true -> Error (BerDecodeError "Invalid LDAP URL: empty port")
    | false ->
        parseSimpleHostPort authority (authority.Substring(0, colon)) (authority.Substring(colon + 1))


///
/// Parse non-bracket authority: bare host, host:port, or unbracketed IPv6.
let private parsePlainAuthority (authority: string) : Result<string option * int option, LdapWireError> =
    match authority.LastIndexOf(':') with
    | -1 -> Ok (Some authority, None)
    | colon -> parseHostPortAtColon authority colon


///
/// Split authority into host option and port option. Supports [IPv6]:port.
let private parseAuthority (authority: string) : Result<string option * int option, LdapWireError> =
    match String.IsNullOrEmpty authority with
    | true -> Ok (None, None)
    | false ->
        match authority.StartsWith("[", StringComparison.Ordinal) with
        | true -> parseBracketedIpv6Authority authority
        | false -> parsePlainAuthority authority


///
/// Strip query string; return path portion only.
let private pathWithoutQuery (pathAndQuery: string) : string =
    match pathAndQuery.IndexOf('?') with
    | -1 -> pathAndQuery
    | q -> pathAndQuery.Substring(0, q)


///
/// Parse path[?query] into optional DN (query ignored for chase).
let private dnFromPathAndQuery (pathAndQuery: string) : string option =
    match pathWithoutQuery pathAndQuery with
    | dnPart when String.IsNullOrEmpty dnPart -> None
    | dnPart -> Some (Uri.UnescapeDataString dnPart)


///
/// Split body after scheme:// into authority and path+query.
let private splitAuthorityAndPath (body: string) : string * string =
    match body.IndexOf('/') with
    | -1 -> body, ""
    | slash -> body.Substring(0, slash), body.Substring(slash + 1)


///
/// Build ParsedLdapUrl once authority components are known.
let private buildParsedLdapUrl (schemeIsSsl: bool) (hostOpt: string option) (portOpt: int option) (pathAndQuery: string) : ParsedLdapUrl =
    { schemeIsSsl = schemeIsSsl
      host = hostOpt
      port = portOpt
      dn = dnFromPathAndQuery pathAndQuery }


///
/// Parse body of an ldap(s) URL after the scheme prefix.
let private parseLdapUrlBody (schemeIsSsl: bool) (body: string) : Result<ParsedLdapUrl, LdapWireError> =
    let authority, pathAndQuery = splitAuthorityAndPath body
    match parseAuthority authority with
    | Error e -> Error e
    | Ok (hostOpt, portOpt) -> Ok (buildParsedLdapUrl schemeIsSsl hostOpt portOpt pathAndQuery)


///
/// Try plain ldap:// scheme.
let private tryParseLdapScheme (trimmed: string) : Result<ParsedLdapUrl, LdapWireError> =
    match trimmed.ToLowerInvariant().StartsWith("ldap://", StringComparison.Ordinal) with
    | true -> parseLdapUrlBody false (trimmed.Substring(7))
    | false -> Error (BerDecodeError "LDAP URL must start with ldap:// or ldaps://")


///
/// Dispatch on ldap:// vs ldaps:// scheme prefix.
let private parseLdapUrlWithScheme (trimmed: string) : Result<ParsedLdapUrl, LdapWireError> =
    match trimmed.ToLowerInvariant().StartsWith("ldaps://", StringComparison.Ordinal) with
    | true -> parseLdapUrlBody true (trimmed.Substring(8))
    | false -> tryParseLdapScheme trimmed


///
/// Parse a non-null trimmed candidate URL string.
let private parseNonEmptyLdapUrl (trimmed: string) : Result<ParsedLdapUrl, LdapWireError> =
    match trimmed.Length with
    | 0 -> Error (BerDecodeError "LDAP URL is empty")
    | _ -> parseLdapUrlWithScheme trimmed


///
/// Parse an LDAP URL for referral chasing. Query components (attrs/scope/filter) are ignored.
let internal parseLdapUrl (uri: string) : Result<ParsedLdapUrl, LdapWireError> =
    match isNull uri with
    | true -> Error (BerDecodeError "LDAP URL is null")
    | false -> parseNonEmptyLdapUrl (uri.Trim())
