module Fiewport.LdapSearch

open System
open System.IO

open Types
open LdapWire


///
/// Map Fiewport's SearchScope to the LDAP wire scope byte.
let private scopeToByte (scope: SearchScope) : byte =
    match scope with
    | Base       -> 0uy
    | OneLevel   -> 1uy
    | Subtree    -> 2uy


///
/// Build the basic unit of LDAP comms
let private buildSearchRequestPDU (config: LdapSearchConfig) =

    match encodeFilter config.filter with
    | Error e -> Error e
    | Ok filterBytes ->
        let scopeByte = scopeToByte config.scope
        let derefAliases = 0uy
        let utf8 = Text.Encoding.UTF8

        let attrBytes =
            config.properties
            |> Array.map (fun a -> encodeBerOctetString (utf8.GetBytes a))
            |> Array.concat
            |> encodeBerSequence

        let searchContent =
            Array.concat
                [ encodeBerOctetString (utf8.GetBytes config.ldapDN)
                  encodeBerEnumerated (int32 scopeByte)
                  encodeBerEnumerated (int32 derefAliases)
                  encodeBerInteger 0
                  encodeBerInteger 0
                  encodeBerBoolean false
                  filterBytes
                  attrBytes ]

        Ok (encodeBerPrimitive 0x63uy searchContent)


///
/// Append decoded SearchResultReference URIs; skip malformed references.
let private accumulateReferenceUris (pdu: byte array) (referrals: string list) : string list =
    match parseSearchReference pdu with
    | Error _ -> referrals
    | Ok uris -> referrals @ uris


///
/// Drain the stream after a SearchRequest: zero or more entries/references,
/// terminated by SearchResultDone. Returns entries, referral URIs, paging cookie, status.
let private drainSearchResponses (stream: Stream) (accEntries: RawLdapEntry list) : Result<RawLdapEntry list * string list * byte array option * SearchResultStatus, LdapWireError> =

    let rec loop entries referrals =
        match receiveMessage stream with
        | Error e -> Error e
        | Ok (SearchResultEntry pdu) ->
            match parseSearchResultEntry pdu with
            | Error e -> Error e
            | Ok entry -> loop (entry :: entries) referrals
        | Ok (SearchReference pdu) ->
            loop entries (accumulateReferenceUris pdu referrals)
        | Ok (SearchResultDone (pdu, controls)) ->
            match parseSearchResultDone pdu with
            | Error e -> Error e
            | Ok (_msgId, status, doneReferrals) ->
                let cookie = readPagedCookie controls
                Ok (List.rev entries, referrals @ doneReferrals, cookie, status)
        | Ok (OtherProtocolOp (tag, _)) ->
            Error (Unexpected $"Unexpected LDAP PDU tag during search: 0x{tag:X2}")

    loop accEntries []


///
/// Whether this page status allows treating the page as usable search data.
let private isUsableSearchStatus (status: SearchResultStatus) : bool =
    match status with
    | Success | SizeLimitExceeded | AdminLimitExceeded | Referral -> true
    | _ -> false


///
/// Continue paging when the server returned a non-empty cookie on a success-class status.
let private shouldContinuePaging (status: SearchResultStatus) (cookie: byte array option) : bool =
    match status, cookie with
    | Referral, _ -> false
    | _, Some c when c.Length > 0 -> true
    | _ -> false


///
/// The main paging loop on one connection; accumulates entries and referral URIs.
let private pagingLoop (stream: Stream) (config: LdapSearchConfig) startMessageId =

    let rec loop (state: PagingState) (cookie: byte array option) =
        match buildSearchRequestPDU config with
        | Error e -> Error e
        | Ok searchReq ->
            let pagedControlBer = encodePagedResultsControl 1000 cookie
            let sdControlBer = encodeSdFlagsControl
            let controlsContent = Array.concat [| pagedControlBer; sdControlBer |]

            let ldapMessage =
                Array.concat
                    [ encodeBerInteger state.messageId
                      searchReq
                      encodeBerPrimitive 0xA0uy controlsContent ]
                |> encodeBerSequence

            stream.Write(ldapMessage, 0, ldapMessage.Length)
            stream.Flush()

            match drainSearchResponses stream [] with
            | Error e -> Error e
            | Ok (pageEntries, pageReferrals, nextCookie, status) ->
                match isUsableSearchStatus status with
                | false -> Error (SearchFailed $"LDAP search failed: {status}")
                | true ->
                    let newEntries = state.entries @ pageEntries
                    let newReferrals = state.referralUris @ pageReferrals
                    match shouldContinuePaging status nextCookie with
                    | true ->
                        loop
                            { entries = newEntries
                              referralUris = newReferrals
                              messageId = state.messageId + 1 }
                            nextCookie
                    | false ->
                        Ok
                            { entries = newEntries
                              referralUris = newReferrals }

    loop { entries = []; referralUris = []; messageId = startMessageId } None


///
/// Perform a paged search on an already-authenticated session (single server, no chase).
/// End-to-end search with transparent referral chase lives in LDAPUtils.doSearch.
let internal searchSession (session: AuthenticatedLdapSession) (config: LdapSearchConfig) : Result<ServerSearchOutcome, LdapWireError> =
    let stream = session.stream
    let startMessageId = AuthenticatedLdapSession.incrementMessageId session
    pagingLoop stream config startMessageId


///
/// Primary endpoint host string used when a referral URI omits the host.
let private primaryHostString (config: LdapSearchConfig) : Result<string, LdapWireError> =
    match String.IsNullOrWhiteSpace config.ldapHostname with
    | false -> Ok (config.ldapHostname.Trim())
    | true ->
        match String.IsNullOrWhiteSpace config.ldapIP with
        | false -> Ok (config.ldapIP.Trim())
        | true -> Error (Unexpected "Cannot resolve referral host: primary config has no ldapHostname or ldapIP")


///
/// Default TCP port for a given TLS choice.
let private defaultPortForSsl (useSsl: bool) : int =
    match useSsl with
    | true -> 636
    | false -> 389


///
/// Transport policy: ldaps forces TLS; ldap://:389 or no port inherits primary; other explicit ports stay plain.
let private resolveChaseTransport (primary: LdapSearchConfig) (parsed: ParsedLdapUrl) : bool * int =
    match parsed.schemeIsSsl with
    | true ->
        let port =
            match parsed.port with
            | Some p -> p
            | None -> 636
        true, port
    | false ->
        match parsed.port with
        | None ->
            primary.useSsl, defaultPortForSsl primary.useSsl
        | Some 389 ->
            primary.useSsl, defaultPortForSsl primary.useSsl
        | Some p ->
            false, p


///
/// Build a visited-set key / chase destination from a parsed URL and the primary search config.
let internal buildReferralTarget (primary: LdapSearchConfig) (parsed: ParsedLdapUrl) : Result<ReferralTarget, LdapWireError> =
    match parsed.host with
    | Some h when not (String.IsNullOrWhiteSpace h) ->
        let useSsl, port = resolveChaseTransport primary parsed
        let baseDn =
            match parsed.dn with
            | Some dn when not (String.IsNullOrWhiteSpace dn) -> dn
            | _ -> primary.ldapDN
        Ok
            { host = h.Trim()
              port = port
              useSsl = useSsl
              baseDn = baseDn }
    | _ ->
        match primaryHostString primary with
        | Error e -> Error e
        | Ok host ->
            let useSsl, port = resolveChaseTransport primary parsed
            let baseDn =
                match parsed.dn with
                | Some dn when not (String.IsNullOrWhiteSpace dn) -> dn
                | _ -> primary.ldapDN
            Ok
                { host = host
                  port = port
                  useSsl = useSsl
                  baseDn = baseDn }


///
/// Normalize for visited-set comparison (host/DN case-insensitive).
let internal normalizeReferralTarget (target: ReferralTarget) : ReferralTarget =
    { host = target.host.ToLowerInvariant()
      port = target.port
      useSsl = target.useSsl
      baseDn = target.baseDn.ToLowerInvariant() }


///
/// ReferralTarget describing the server we already searched as the primary.
let internal primaryReferralTarget (config: LdapSearchConfig) : Result<ReferralTarget, LdapWireError> =
    match primaryHostString config with
    | Error e -> Error e
    | Ok host ->
        normalizeReferralTarget
            { host = host
              port = config.ldapPort
              useSsl = config.useSsl
              baseDn = config.ldapDN }
        |> Ok


///
/// Map a chase target onto a search config: same filter/scope/attrs; host/port/ssl/dn from target.
let internal buildChaseConfig (original: LdapSearchConfig) (target: ReferralTarget) : LdapSearchConfig =
    match hostLooksLikeIp target.host with
    | true ->
        { original with
            ldapHostname = ""
            ldapIP = target.host
            ldapPort = target.port
            useSsl = target.useSsl
            ldapDN = target.baseDn }
    | false ->
        { original with
            ldapHostname = target.host
            ldapIP = ""
            ldapPort = target.port
            useSsl = target.useSsl
            ldapDN = target.baseDn }


///
/// Turn a referral URI into a normalized target, or skip if unparsable.
let private tryReferralTarget (primary: LdapSearchConfig) (uri: string) : ReferralTarget option =
    match parseLdapUrl uri with
    | Error _ -> None
    | Ok parsed ->
        match buildReferralTarget primary parsed with
        | Error _ -> None
        | Ok target -> Some (normalizeReferralTarget target)


///
/// Finalize chase: empty result with only abandoned branches → bind failure; else entries.
let private finalizeChase (state: ChaseState) : Result<RawLdapEntry list, LdapWireError> =
    match state.entries, state.abandonedAuth with
    | [], true ->
        Error (BindFailed "Referral chase failed: could not reach any referred server with the supplied credentials")
    | entries, _ ->
        Ok entries


///
/// Record a failed chase branch and continue with remaining URIs.
let private abandonChaseTarget (state: ChaseState) (target: ReferralTarget) (rest: string list) : ChaseState =
    { visited = state.visited.Add target
      entries = state.entries
      queue = rest
      abandonedAuth = true }


///
/// Merge a successful chase branch into accumulator state.
let private mergeChaseOutcome (state: ChaseState) (target: ReferralTarget) (rest: string list) (outcome: ServerSearchOutcome) : ChaseState =
    { visited = state.visited.Add target
      entries = state.entries @ outcome.entries
      queue = rest @ outcome.referralUris
      abandonedAuth = state.abandonedAuth }


///
/// Transparent referral chase: visited-set loop detection, credential reuse via injected search.
/// Chase-branch failures are soft: keep prior entries; empty+all-failed → BindFailed.
let internal chaseReferrals (searchOneServer: SearchOneServer) (original: LdapSearchConfig) (primaryTarget: ReferralTarget) (seedEntries: RawLdapEntry list) (seedUris: string list) : Result<RawLdapEntry list, LdapWireError> =

    let rec loop (state: ChaseState) =
        match state.queue with
        | [] -> finalizeChase state
        | uri :: rest ->
            match tryReferralTarget original uri with
            | None ->
                loop { state with queue = rest }
            | Some target when state.visited.Contains target ->
                loop { state with queue = rest }
            | Some target ->
                let chaseConfig = buildChaseConfig original target
                match searchOneServer chaseConfig with
                | Error _ ->
                    loop (abandonChaseTarget state target rest)
                | Ok outcome ->
                    loop (mergeChaseOutcome state target rest outcome)

    loop
        { visited = Set.singleton primaryTarget
          entries = seedEntries
          queue = seedUris
          abandonedAuth = false }


///
/// Single-server paged search on an existing session (no referral chase).
let internal doSearch session config =
    match searchSession session config with
    | Error e -> Error e
    | Ok outcome -> Ok outcome.entries
