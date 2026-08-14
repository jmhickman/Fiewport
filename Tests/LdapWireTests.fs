namespace Fiewport.Tests

module LdapWireTests =

    open System
    open System.IO
    open System.Text
    open Expecto
    open Fiewport.LdapWire
    open Fiewport.Types


    let private hexToBytes (hex: string) : byte array =
        hex.Split([| ' ' |], StringSplitOptions.RemoveEmptyEntries)
        |> Array.map (fun s -> Byte.Parse(s, Globalization.NumberStyles.HexNumber, null))

    let private tlvValue (tlv: byte array) : byte array =
        let value, _ = parseBerTlv tlv 0
        value


    let private contentTlvs (tlv: byte array) : byte array list =
        let value = tlvValue tlv
        match parseBerSequence (encodeBerSequence value) with
        | Ok children -> children
        | Error e -> failtest $"contentTlvs failed: {e}"


    let private utf8 = Encoding.UTF8


    let private expectOk (result: Result<'a, LdapWireError>) : 'a =
        match result with
        | Ok v -> v
        | Error e -> failtest $"Expected Ok, got Error: {e}"


    let private streamOf (bytes: byte array) : MemoryStream =
        let ms = new MemoryStream()
        ms.Write(bytes, 0, bytes.Length)
        ms.Position <- 0L
        ms


    let private berPrimitiveTests =
        testList "BER primitives"
            [ test "INTEGER 0 / 1 / 1000 / -1 encode canonically" {
                  Expect.equal (encodeBerInteger 0)    (hexToBytes "02 01 00")       "0"
                  Expect.equal (encodeBerInteger 1)    (hexToBytes "02 01 01")       "1"
                  Expect.equal (encodeBerInteger 1000) (hexToBytes "02 02 03 e8")    "1000"
                  Expect.equal (encodeBerInteger -1)   (hexToBytes "02 01 ff")       "-1"
              }

              test "INTEGER round-trips through parseBerIntegerBytes" {
                  [ 0; 1; 127; 128; 1000; -1; -128 ]
                  |> List.iter (fun n ->
                      let decoded = encodeBerInteger n |> parseBerIntegerBytes |> expectOk
                      Expect.equal decoded n $"round-trip {n}")
              }

              test "OCTET STRING and SEQUENCE wrap content" {
                  Expect.equal
                      (encodeBerOctetString (utf8.GetBytes "test"))
                      (hexToBytes "04 04 74 65 73 74")
                      "OCTET STRING 'test'"
                  Expect.equal
                      (encodeBerSequence [| 0x01uy; 0x02uy; 0x03uy |])
                      (hexToBytes "30 03 01 02 03")
                      "SEQUENCE"
              }

              test "parseBerSequence yields child TLVs" {
                  let fields =
                      hexToBytes "30 0a 02 01 05 04 05 68 65 6c 6c 6f"
                      |> parseBerSequence
                      |> expectOk
                  Expect.equal fields.Length 2 "two children"
                  Expect.equal fields.[0] (hexToBytes "02 01 05") "INTEGER 5"
                  Expect.equal fields.[1] (hexToBytes "04 05 68 65 6c 6c 6f") "OCTET STRING hello"
              }

              test "parseBerTlv handles long-form length (AD style 0x84)" {
                  let input = hexToBytes "04 84 00 00 00 04 74 65 73 74"
                  let value, next = parseBerTlv input 0
                  Expect.equal value (utf8.GetBytes "test") "value"
                  Expect.equal next input.Length "consumed all"
              } ]


    let private framingTests =
        testList "Framing"
            [ test "encodeLdapMessage does not add a length prefix" {
                  let pdu = hexToBytes "30 03 02 01 01"
                  let framed = encodeLdapMessage pdu
                  Expect.equal framed pdu "identity framing — LDAP/TCP is bare BER"
                  Expect.equal framed.[0] 0x30uy "still SEQUENCE"
              }

              test "receiveMessage reads one bare-BER LDAPMessage from the stream" {
                  let doneMsg = hexToBytes "30 0c 02 01 02 65 07 0a 01 00 04 00 04 00"
                  use ms = streamOf doneMsg
                  match receiveMessage ms with
                  | Ok (SearchResultDone (pdu, controls)) ->
                      Expect.equal pdu.[0] 0x65uy "APPLICATION 5"
                      Expect.isNone controls "no controls"
                      let _, status = parseSearchResultDone pdu |> expectOk
                      Expect.equal status Success "success"
                  | Ok other -> failtest $"unexpected message: {other}"
                  | Error e -> failtest $"receive failed: {e}"
              }

              test "receiveMessage handles AD long-form definite length (0x84)" {
                  let doneMsg = hexToBytes "30 84 00 00 00 0c 02 01 02 65 07 0a 01 00 04 00 04 00"
                  use ms = streamOf doneMsg
                  match receiveMessage ms with
                  | Ok (SearchResultDone (pdu, _)) ->
                      Expect.equal pdu.[0] 0x65uy "APPLICATION 5"
                  | Ok other -> failtest $"unexpected: {other}"
                  | Error e -> failtest $"receive failed: {e}"
              }

              test "receiveMessage classifies SearchResultEntry" {
                  let dn = encodeBerOctetString (utf8.GetBytes "cn=x")
                  let attrs = encodeBerSequence [||]
                  let entry = encodeBerPrimitive 0x64uy (Array.concat [| dn; attrs |])
                  let msg = encodeBerSequence (Array.concat [| encodeBerInteger 1; entry |])
                  use ms = streamOf msg
                  match receiveMessage ms with
                  | Ok (SearchResultEntry pdu) ->
                      let parsed = parseSearchResultEntry pdu |> expectOk
                      Expect.equal parsed.DN "cn=x" "DN"
                  | Ok other -> failtest $"unexpected: {other}"
                  | Error e -> failtest $"receive failed: {e}"
              }

              test "receiveMessage captures [0] controls on SearchResultDone" {
                  let doneMsg = hexToBytes "30 0e 02 01 02 65 07 0a 01 00 04 00 04 00 a0 00"
                  use ms = streamOf doneMsg
                  match receiveMessage ms with
                  | Ok (SearchResultDone (_, Some controls)) ->
                      Expect.equal controls.[0] 0xA0uy "controls context tag"
                  | Ok (SearchResultDone (_, None)) ->
                      failtest "expected controls to be captured"
                  | Ok other -> failtest $"unexpected: {other}"
                  | Error e -> failtest $"receive failed: {e}"
              }

              test "sendMessage then receiveMessage round-trips a Done response shape" {
                  use ms = new MemoryStream()
                  let protocolOp = encodeBerPrimitive 0x63uy (encodeBerOctetString (utf8.GetBytes "dc=x"))
                  sendMessage ms 7 protocolOp
                  let written = ms.ToArray()
                  Expect.equal written.[0] 0x30uy "bare BER SEQUENCE — no length prefix"
                  let fields = parseBerSequence written |> expectOk
                  match fields with
                  | msgId :: op :: _ ->
                      Expect.equal (parseBerIntegerBytes msgId |> expectOk) 7 "message id"
                      Expect.equal op.[0] 0x63uy "SearchRequest tag"
                  | _ -> failtest "expected message id + protocolOp"
              } ]


    let private filterTests =
        testList "Filter encoding"
            [ test "equalityMatch encodes as [3] IMPLICIT with attr + value" {
                  let ber = encodeFilter "(objectClass=domain)" |> expectOk
                  Expect.equal ber.[0] 0xA3uy "tag [3] constructed"
                  let children = contentTlvs ber
                  Expect.equal children.Length 2 "attr + value"
                  Expect.equal (tlvValue children.[0] |> utf8.GetString) "objectClass" "attr"
                  Expect.equal (tlvValue children.[1] |> utf8.GetString) "domain" "value"
              }

              test "present encodes as [7] primitive AttributeDescription" {
                  let ber = encodeFilter "(objectClass=*)" |> expectOk
                  Expect.equal ber.[0] 0x87uy "tag [7] primitive"
                  Expect.equal (tlvValue ber |> utf8.GetString) "objectClass" "attr"
              }

              test "OR of two equality matches" {
                  let ber = encodeFilter "(|(objectCategory=person)(objectCategory=user))" |> expectOk
                  Expect.equal ber.[0] 0xA1uy "OR tag [1]"
                  let children = contentTlvs ber
                  Expect.equal children.Length 2 "two clauses"
                  Expect.equal children.[0].[0] 0xA3uy "first is equality"
                  Expect.equal children.[1].[0] 0xA3uy "second is equality"
              }

              test "AND / NOT nest correctly" {
                  let ber = encodeFilter "(&(objectClass=user)(!(cn=krbtgt)))" |> expectOk
                  Expect.equal ber.[0] 0xA0uy "AND tag [0]"
                  let children = contentTlvs ber
                  Expect.equal children.Length 2 "two children"
                  Expect.equal children.[0].[0] 0xA3uy "equality"
                  Expect.equal children.[1].[0] 0xA2uy "NOT"
              }

              test "substring filter uses initial/any/final components" {
                  let ber = encodeFilter "(operatingSystem=*server*)" |> expectOk
                  Expect.equal ber.[0] 0xA4uy "substrings tag [4]"
                  let children = contentTlvs ber
                  // attr + one 'any' component [1]
                  Expect.isGreaterThan children.Length 1 "attr + components"
                  Expect.equal (tlvValue children.[0] |> utf8.GetString) "operatingSystem" "attr"
                  let componentTags = children |> List.skip 1 |> List.map (fun c -> c.[0])
                  Expect.isTrue (List.contains 0x81uy componentTags) "has 'any' [1] component"
              }

              test "extensible match encodes UAC bitwise AND filter" {
                  let ber =
                      encodeFilter "(userAccountControl:1.2.840.113556.1.4.803:=8192)"
                      |> expectOk
                  Expect.equal ber.[0] 0xA9uy "extensibleMatch tag [9]"
                  let children = contentTlvs ber
                  let values = children |> List.map (fun c -> c.[0], tlvValue c |> utf8.GetString)
                  Expect.isTrue (values |> List.exists (fun (t, v) -> t = 0x81uy && v = "1.2.840.113556.1.4.803")) "matchingRule"
                  Expect.isTrue (values |> List.exists (fun (t, v) -> t = 0x82uy && v = "userAccountControl")) "type"
                  Expect.isTrue (values |> List.exists (fun (t, v) -> t = 0x83uy && v = "8192")) "matchValue"
              }

              test "empty filter defaults to present objectClass" {
                  let ber = encodeFilter "" |> expectOk
                  Expect.equal ber.[0] 0x87uy "present"
                  Expect.equal (tlvValue ber |> utf8.GetString) "objectClass" "objectClass"
              }

              test "filter is never encoded as OCTET STRING of the filter text" {
                  let ber = encodeFilter "(objectClass=domain)" |> expectOk
                  Expect.notEqual ber.[0] 0x04uy "must not be bare OCTET STRING"
                  let asText = try utf8.GetString(tlvValue ber) with _ -> ""
                  Expect.isFalse (asText.Contains "(") "value is not the filter source text"
              }

              test "unbalanced parentheses return BerDecodeError" {
                  match encodeFilter "(objectClass=user" with
                  | Error (BerDecodeError _) -> ()
                  | other -> failtest $"expected BerDecodeError, got {other}"
              } ]


    let private searchRequestTests =
        testList "SearchRequest"
            [ test "encodeSearchRequest builds APPLICATION 3 with Filter CHOICE, not text" {
                  let encoded =
                      encodeSearchRequest
                          2 "dc=example,dc=com" 2uy 0uy 1000 30 false
                          "(&(objectClass=person)(uid=jdoe))"
                          [| "*"; "+" |]

                  Expect.equal encoded.[0] 0x30uy "outer LDAPMessage SEQUENCE"
                  let fields = parseBerSequence encoded |> expectOk
                  match fields with
                  | msgId :: searchReq :: _ ->
                      Expect.equal (parseBerIntegerBytes msgId |> expectOk) 2 "messageId"
                      Expect.equal searchReq.[0] 0x63uy "APPLICATION 3"
                      let body = contentTlvs searchReq
                      Expect.isGreaterThanOrEqual body.Length 8 "full SearchRequest fields"
                      Expect.equal (tlvValue body.[0] |> utf8.GetString) "dc=example,dc=com" "base DN"
                      Expect.equal body.[1].[0] 0x0Auy "scope ENUMERATED"
                      Expect.equal body.[6].[0] 0xA0uy "filter is AND CHOICE, not OCTET STRING"
                      Expect.notEqual body.[6].[0] 0x04uy "filter must not be OCTET STRING text"
                  | _ -> failtest "expected messageId + SearchRequest"
              }

              test "base-scope domain SID style request uses equality filter and attr list" {
                  let encoded =
                      encodeSearchRequest
                          3 "DC=ad-lab,DC=local" 0uy 0uy 0 0 false
                          "(objectClass=domain)"
                          [| "objectSid" |]
                  let searchReq =
                      match parseBerSequence encoded |> expectOk with
                      | _ :: req :: _ -> req
                      | _ -> failtest "missing SearchRequest"
                  let body = contentTlvs searchReq
                  Expect.equal body.[1] (encodeBerEnumerated 0) "scope base"
                  Expect.equal body.[6].[0] 0xA3uy "equality filter"
                  let attrs = contentTlvs body.[7]
                  Expect.equal (tlvValue attrs.[0] |> utf8.GetString) "objectSid" "requested attr"
              } ]


    let private responseTests =
        testList "Response parsing"
            [ test "parseSearchResultEntry decodes ldap.com sample (full LDAPMessage)" {
                  let wire =
                      hexToBytes
                          "30 49 02 01 02 64 44 04 11 64 63 3d 65 78 61 6d 70 6c 65 2c 64 63 3d 63 6f 6d 30 2f 30 1c 04 0b 6f 62 6a 65 63 74 43 6c 61 73 73 31 0d 04 03 74 6f 70 04 06 64 6f 6d 61 69 6e 30 0f 04 02 64 63 31 09 04 07 65 78 61 6d 70 6c 65"
                  let entry = parseSearchResultEntry wire |> expectOk
                  Expect.equal entry.DN "dc=example,dc=com" "DN"
                  let oc = entry.Attributes.["objectclass"] |> List.map utf8.GetString
                  Expect.equal (List.sort oc) [ "domain"; "top" ] "objectClass values"
                  Expect.equal (entry.Attributes.["dc"] |> List.map utf8.GetString) [ "example" ] "dc"
              }

              test "parseSearchResultEntry accepts bare APPLICATION 4 PDU from receiveMessage" {
                  let dn = encodeBerOctetString (utf8.GetBytes "cn=test,dc=example,dc=com")
                  let cnVal = encodeBerPrimitive 0x31uy (encodeBerOctetString (utf8.GetBytes "test"))
                  let cnAttr =
                      encodeBerSequence
                          (Array.concat [| encodeBerOctetString (utf8.GetBytes "cn"); cnVal |])
                  let attrs = encodeBerSequence cnAttr
                  let pdu = encodeBerPrimitive 0x64uy (Array.concat [| dn; attrs |])
                  let entry = parseSearchResultEntry pdu |> expectOk
                  Expect.equal entry.DN "cn=test,dc=example,dc=com" "DN"
                  Expect.equal (utf8.GetString entry.Attributes.["cn"].[0]) "test" "cn"
              }

              test "parseSearchResultDone accepts ENUMERATED resultCode (AD wire shape)" {
                  let pdu = hexToBytes "65 07 0a 01 00 04 00 04 00"
                  let _, status = parseSearchResultDone pdu |> expectOk
                  Expect.equal status Success "success via ENUMERATED"
              }

              test "parseSearchResultDone accepts full LDAPMessage with INTEGER resultCode" {
                  let wire = hexToBytes "30 0c 02 01 02 65 07 02 01 00 04 00 04 00"
                  let msgId, status = parseSearchResultDone wire |> expectOk
                  Expect.equal msgId 2 "message id"
                  Expect.equal status Success "success"
              }

              test "parseSearchResultDone maps non-zero result codes" {
                  // APPLICATION 5, ENUMERATED 32 (noSuchObject)
                  let pdu = hexToBytes "65 07 0a 01 20 04 00 04 00"
                  let _, status = parseSearchResultDone pdu |> expectOk
                  Expect.equal status NoSuchObject "noSuchObject"
              }

              test "parseSearchReference decodes two referral URIs" {
                  let wire =
                      hexToBytes
                          "30 6d 02 01 02 73 68 04 32 6c 64 61 70 3a 2f 2f 64 73 31 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d 3a 33 38 39 2f 64 63 3d 65 78 61 6d 70 6c 65 2c 64 63 3d 63 6f 6d 3f 3f 73 75 62 3f 04 32 6c 64 61 70 3a 2f 2f 64 73 32 2e 65 78 61 6d 70 6c 65 2e 63 6f 6d 3a 33 38 39 2f 64 63 3d 65 78 61 6d 70 6c 65 2c 64 63 3d 63 6f 6d 3f 3f 73 75 62 3f"
                  let uris = parseSearchReference wire |> expectOk
                  Expect.equal uris.Length 2 "two URIs"
                  Expect.isTrue (List.contains "ldap://ds1.example.com:389/dc=example,dc=com??sub?" uris) "ds1"
                  Expect.isTrue (List.contains "ldap://ds2.example.com:389/dc=example,dc=com??sub?" uris) "ds2"
              }

              test "SearchResultStatus.FromCode covers the codes Searcher surfaces" {
                  Expect.equal (SearchResultStatus.FromCode 0) Success "0 success"
                  Expect.equal (SearchResultStatus.FromCode 4) SizeLimitExceeded "4 sizeLimit"
                  Expect.equal (SearchResultStatus.FromCode 10) Referral "10 referral"
                  Expect.equal (SearchResultStatus.FromCode 11) AdminLimitExceeded "11 adminLimit"
                  Expect.equal (SearchResultStatus.FromCode 12) UnavailableCriticalExtension "12 unavailableCriticalExtension"
                  Expect.equal (SearchResultStatus.FromCode 32) NoSuchObject "32 noSuchObject"
                  Expect.equal (SearchResultStatus.FromCode 49) InvalidCredentials "49 invalidCredentials"
                  Expect.equal (SearchResultStatus.FromCode 50) InsufficientAccessRights "50 insufficientAccessRights"
                  match SearchResultStatus.FromCode 99 with
                  | Other msg -> Expect.stringContains msg "99" "unknown code"
                  | other -> failtest $"expected Other, got {other}"
              } ]


    let private controlTests =
        testList "Controls"
            [ test "SD Flags control is a full Control SEQUENCE with OID and OCTET STRING value" {
                  let encoded = encodeSdFlagsControl
                  Expect.equal encoded.[0] 0x30uy "Control SEQUENCE"
                  let fields = parseBerSequence encoded |> expectOk
                  match fields with
                  | oidTlv :: rest ->
                      Expect.equal (tlvValue oidTlv |> Encoding.ASCII.GetString) "1.2.840.113556.1.4.801" "OID"
                      let valueTlv = List.last rest
                      Expect.equal valueTlv.[0] 0x04uy "controlValue OCTET STRING"
                      let inner = parseBerSequence (tlvValue valueTlv) |> expectOk
                      Expect.equal (parseBerIntegerBytes inner.[0] |> expectOk) 7 "OWNER|GROUP|DACL"
                  | _ -> failtest "empty control"
              }

              test "paged results control encodes pageSize and empty initial cookie" {
                  let encoded = encodePagedResultsControl 1000 None
                  let fields = parseBerSequence encoded |> expectOk
                  let oid = tlvValue fields.[0] |> Encoding.ASCII.GetString
                  Expect.equal oid "1.2.840.113556.1.4.319" "OID"
                  let valueTlv = List.last fields
                  Expect.equal valueTlv.[0] 0x04uy "controlValue is OCTET STRING"
                  match parseBerSequence (tlvValue valueTlv) |> expectOk with
                  | [ pageSize; cookie ] ->
                      Expect.equal (parseBerIntegerBytes pageSize |> expectOk) 1000 "pageSize"
                      Expect.equal (tlvValue cookie) [||] "empty cookie"
                  | _ -> failtest "expected pageSize + cookie"
              }

              test "paged results control preserves non-empty cookie bytes" {
                  let cookie = [| 0xDEuy; 0xADuy; 0xBEuy; 0xEFuy |]
                  let encoded = encodePagedResultsControl 500 (Some cookie)
                  let valueTlv = parseBerSequence encoded |> expectOk |> List.last
                  match parseBerSequence (tlvValue valueTlv) |> expectOk with
                  | [ _; cookieTlv ] -> Expect.equal (tlvValue cookieTlv) cookie "cookie"
                  | _ -> failtest "bad control value"
              }

              test "readPagedCookie extracts cookie from [0] IMPLICIT controls wrapper" {
                  let cookie = [| 0x01uy; 0x02uy; 0x03uy; 0x04uy |]
                  let control = encodePagedResultsControl 1000 (Some cookie)
                  let controlsA0 = encodeBerPrimitive 0xA0uy control
                  match readPagedCookie (Some controlsA0) with
                  | Some c -> Expect.equal c cookie "cookie extracted through A0 wrapper"
                  | None -> failtest "expected cookie"
              }

              test "readPagedCookie returns None for empty cookie (search complete)" {
                  let control = encodePagedResultsControl 1000 None
                  let controlsA0 = encodeBerPrimitive 0xA0uy control
                  Expect.isNone (readPagedCookie (Some controlsA0)) "empty cookie => None"
                  Expect.isNone (readPagedCookie None) "missing controls => None"
              }

              test "LDAPMessage layout places controls after protocolOp, not nested inside it" {
                  let msgId = encodeBerInteger 1
                  let searchReq = encodeBerPrimitive 0x63uy (hexToBytes "04 01 78")
                  let controls = encodeBerPrimitive 0xA0uy (encodePagedResultsControl 100 None)
                  let ldapMessage =
                      Array.concat [| msgId; searchReq; controls |]
                      |> encodeBerSequence
                  match parseBerSequence ldapMessage |> expectOk with
                  | [ id; op; ctrl ] ->
                      Expect.equal (parseBerIntegerBytes id |> expectOk) 1 "msgId"
                      Expect.equal op.[0] 0x63uy "protocolOp is APPLICATION 3"
                      Expect.equal ctrl.[0] 0xA0uy "controls sibling [0]"
                  | fields -> failtest $"expected 3 top-level fields, got {fields.Length}"
              } ]

    let allTests =
        testList "LdapWire"
            [ berPrimitiveTests
              framingTests
              filterTests
              searchRequestTests
              responseTests
              controlTests ]
