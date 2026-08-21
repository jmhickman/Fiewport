namespace Fiewport

[<AutoOpen>]
module Types =

    open MessagePack
    open Fauli.Domain

    /// <summary>Search scope for LDAP queries.</summary>
    type SearchScope =
        | Base
        | OneLevel
        | Subtree

    ///
    /// Representation of unboxed data from an LDAP query.
    /// Some of these datatypes are speculation and aren't confirmed in real results.
    /// I have access to a limited AD that is very simplistic, so verifying all of these is likely
    /// impossible for me alone.
    /// 
    type internal ADDataTypes =       
        | ADBytes of byte array 
        | ADString of string 
        

    type internal RawLdapEntry =
        { DN : string
          Attributes : Map<string, byte array list> }    


    ///
    /// <summary>
    /// Authentication credentials for LDAP connection.
    /// Lives only in the connection layer — never serialized, never persisted.
    /// </summary>
    ///
    type LdapCredentials =
        { username: string
          password: string }


    ///
    /// <summary>
    /// LDAP search configuration
    /// Embedded in <c>LDAPSearchResult</c> for downstream analysis of search parameters.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>ldapHostname</c> and <c>ldapIP</c> are independent; either or both may be set.
    /// Use empty string (<c>""</c>) when a value is unknown — not <c>null</c>, not optional fields.
    /// </para>
    /// <para>
    /// Kerberos needs the full AD server hostname, if you do not provide TGT material.
    /// IP-only typically results in NTLM authentication because AD has no <c>ldap/&lt;ip&gt;</c> SPN.
    /// </para>
    /// </remarks>
    ///
    [<MessagePackObject>]
    type LdapSearchConfig =
        { [<Key(0)>] properties: string array
          [<Key(1)>] filter: string
          [<Key(2)>] ldapDN: string
          [<Key(3)>] scope: SearchScope
          [<Key(4)>] ldapHostname: string
          [<Key(5)>] ldapIP: string
          [<Key(6)>] ldapPort: int
          [<Key(7)>] useSsl: bool }

    ///
    /// <summary>
    /// Public-facing config: wraps the LDAP details with credentials.
    /// Consumed at the connection boundary; credentials are stripped before
    /// the config enters the serializable pipeline.
    /// </summary>
    ///
    type SearcherConfig =
        { ldapDetails: LdapSearchConfig
          credentials: LdapCredentials }
        
    ///
    /// <summary>Defines the batteries-included searches</summary> 
    [<MessagePackObject>]
    type LDAPSearchType =
        | [<Key(0)>] GetUsers
        | [<Key(1)>] GetComputers
        | [<Key(2)>] GetSites
        | [<Key(3)>] GetOUs
        | [<Key(4)>] GetGroups
        | [<Key(5)>] GetDomainDNSZones
        | [<Key(6)>] GetDNSRecords
        | [<Key(7)>] GetDomainSubnets
        | [<Key(8)>] GetDFSShares
        | [<Key(9)>] GetGroupPolicyObjects
        | [<Key(10)>] GetDomainTrusts
        | [<Key(11)>] GetDomainObjects
        | [<Key(12)>] GetDomainControllers
        | [<Key(13)>] GetHostsTrustedForDelegation
        | [<Key(14)>] GetReportedServersNotDC
        | [<Key(15)>] GetContainers
        | [<Key(16)>] GetUsersWithSPNs
        | [<Key(17)>] GetConstrainedDelegates
        | [<Key(18)>] GetASREPTargets
        | [<Key(19)>] GetKerberoastTargets
        | [<Key(20)>] GetProtectedUsers
        | [<Key(21)>] GetGroupsWithLocalAdminRights
        | [<Key(22)>] DumpAD
        | [<Key(23)>] GetGroupMembers
        | [<Key(24)>] GetGMSAs
        | [<Key(25)>] GetUsersWithSidHistory
        | [<Key(26)>] GetUsersWithAdminCount
        | [<Key(27)>] GetMachineAccountQuota
        | [<Key(28)>] GetForestDomains
        | [<Key(29)>] GetForestGlobalCatalogs
        | [<Key(30)>] GetForestTrusts
        | [<Key(31)>] GetDomainSID
        | [<Key(32)>] GetDefaultPasswordPolicy
        | [<Key(33)>] GetGroup
        | [<Key(34)>] GetLaps
        | [<Key(35)>] GetLapsRights
    
    
    ///
    /// <summary>Represents a single LDAP entry as a map of attribute names to decoded string values.</summary>
    type internal LDAPEntryData = Map<string, string list>


    ///
    /// <summary>Represents an error from the LDAP infrastructure layer.</summary>
    /// <param name="context">Where the error occurred: "bind", "search", or "iterate".</param>
    ///
    [<MessagePackObject>]
    type LdapError =
        { [<Key(0)>]message: string
          [<Key(1)>]context: string }


    ///
    /// <summary>
    /// Represents the result of an LDAP search. An AD has an arbitrary number of attributes, and all
    /// results are stored in the <c>Map</c>.
    /// </summary>
    ///
    [<MessagePackObject>]
    type LDAPSearchResult =
        { [<Key(0)>]searchType: LDAPSearchType 
          [<Key(1)>]searchConfig: LdapSearchConfig
          [<Key(2)>]ldapSearcherError: LdapError option
          [<Key(3)>]ldapData: LDAPEntryData list
          [<Key(4)>]authenticationMethod: Fauli.Domain.AuthenticationMethod option }

    
    ///
    /// <summary>Defines a Filter for the <c>Tee</c></summary>    
    type Filter = LDAPSearchResult list -> LDAPSearchResult list
    
    
    ///
    /// <summary>Defines a Mold for the <c>Tee</c></summary>    
    type Mold<'T> = LDAPSearchResult list -> 'T
    
    
    ///
    /// <summary>Defines a FilterAction for the <c>Tee</c></summary>    
    type FilterAction = LDAPSearchResult list -> unit
    
    
    ///
    /// <summary>Defines a MoldAction for the <c>Tee</c></summary>
    type MoldAction<'T> = 'T -> unit


    ///
    /// <summary>
    /// Error type for the raw LDAP wire protocol layer.
    /// Each case represents a distinct failure mode so callers can handle
    /// connection, bind, and protocol errors exhaustively.
    /// </summary>
    ///
    [<MessagePackObject>]
    type LdapWireError =
        | [<Key(0)>] ConnectionFailed of string
        | [<Key(1)>] BindFailed of string
        | [<Key(2)>] SearchFailed of string
        | [<Key(3)>] BerDecodeError of string
        | [<Key(4)>] Timeout of string
        | [<Key(5)>] Unexpected of string


    ///
    /// An LDAP message received from the wire.
    /// PDUs are the protocolOp TLVs (e.g. APPLICATION 4/5/19). Controls, when
    /// present on SearchResultDone, are the raw [0] context TLV.
    ///
    type internal LdapMessage =
        | SearchResultEntry of pdu: byte array
        | SearchResultDone of pdu: byte array * controls: byte array option
        | SearchReference of pdu: byte array
        | OtherProtocolOp of tag: byte * pdu: byte array


    ///
    /// Result code from a SearchResultDone response (RFC 4511 §4.1.9).
    type internal SearchResultStatus =
        | Success
        | OperationsError
        | ProtocolError
        | TimeLimitExceeded
        | SizeLimitExceeded
        | CompareFalse
        | CompareTrue
        | AuthMethodNotSupported
        | StrongerAuthRequired
        | Referral
        | AdminLimitExceeded
        | UnavailableCriticalExtension
        | ConfidentialityRequired
        | SaslBindInProgress
        | NoSuchAttribute
        | UndefinedAttributeType
        | InappropriateMatching
        | ConstraintViolation
        | AttributeOrValueExists
        | InvalidAttributeSyntax
        | NoSuchObject
        | AliasProblem
        | InvalidDNSyntax
        | AliasDereferencingProblem
        | InappropriateAuthentication
        | InvalidCredentials
        | InsufficientAccessRights
        | Busy
        | Unavailable
        | UnwillingToPerform
        | LoopDetect
        | NamingViolation
        | ObjectClassViolation
        | NotAllowedOnNonLeaf
        | NotAllowedOnRDN
        | EntryAlreadyExists
        | ObjectClassModsProhibited
        | AffectsMultipleDSAs
        | Other of string

        static member FromCode (code: int32) : SearchResultStatus =
            match code with
            | 0  -> Success
            | 1  -> OperationsError
            | 2  -> ProtocolError
            | 3  -> TimeLimitExceeded
            | 4  -> SizeLimitExceeded
            | 5  -> CompareFalse
            | 6  -> CompareTrue
            | 7  -> AuthMethodNotSupported
            | 8  -> StrongerAuthRequired
            | 10 -> Referral
            | 11 -> AdminLimitExceeded
            | 12 -> UnavailableCriticalExtension
            | 13 -> ConfidentialityRequired
            | 14 -> SaslBindInProgress
            | 16 -> NoSuchAttribute
            | 17 -> UndefinedAttributeType
            | 18 -> InappropriateMatching
            | 19 -> ConstraintViolation
            | 20 -> AttributeOrValueExists
            | 21 -> InvalidAttributeSyntax
            | 32 -> NoSuchObject
            | 33 -> AliasProblem
            | 34 -> InvalidDNSyntax
            | 36 -> AliasDereferencingProblem
            | 48 -> InappropriateAuthentication
            | 49 -> InvalidCredentials
            | 50 -> InsufficientAccessRights
            | 51 -> Busy
            | 52 -> Unavailable
            | 53 -> UnwillingToPerform
            | 54 -> LoopDetect
            | 64 -> NamingViolation
            | 65 -> ObjectClassViolation
            | 66 -> NotAllowedOnNonLeaf
            | 67 -> NotAllowedOnRDN
            | 68 -> EntryAlreadyExists
            | 69 -> ObjectClassModsProhibited
            | 71 -> AffectsMultipleDSAs
            | _  -> Other $"LDAP error code {code}"


    ///
    /// Components of an LDAP(S) URL relevant to referral chasing (RFC 4516).
    type internal ParsedLdapUrl =
        { schemeIsSsl : bool
          host : string option
          port : int option
          dn : string option }


    ///
    /// Normalized chase destination — visited-set key and config seed.
    type internal ReferralTarget =
        { host : string
          port : int
          useSsl : bool
          baseDn : string }


    ///
    /// State threaded through the paging loop on a single server.
    type internal PagingState =
        { entries : RawLdapEntry list
          referralUris : string list
          messageId : int32 }


    ///
    /// State threaded through transparent referral chase.
    type internal ChaseState =
        { visited : Set<ReferralTarget>
          entries : RawLdapEntry list
          queue : string list
          abandonedAuth : bool }


    ///
    /// One server's search outcome before chase: entries plus referral URI strings.
    type internal ServerSearchOutcome =
        { entries : RawLdapEntry list
          referralUris : string list }


    ///
    /// Injected dependency: bind+search a single server (no nested chase).
    type internal SearchOneServer = LdapSearchConfig -> Result<ServerSearchOutcome, LdapWireError>


    ///
    /// Outcome of inspecting one Control TLV while hunting the paged-results cookie.
    type internal CookieSearchStep =
        | CookieFound of byte array option
        | KeepSearching


    ///
    /// Split of an LDAPMessage or bare protocolOp: optional message id, PDU TLV, optional controls.
    type internal WireSplit = int32 option * byte array * byte array option


    ///
    /// Resolved Fauli host roles after applying ldapHostname / ldapIP rules.
    ///
    type internal ResolvedLdapEndpoints =
        { connectHost : string
          kdcHost : string
          spnHost : string }


    ///
    /// Fauli Host triple used to build an AuthenticationRequest.
    type internal ResolvedFauliHosts =
        { connectHost : Fauli.Domain.Host
          kdcHost : Fauli.Domain.Host
          spnHost : Fauli.Domain.Host }


    ///
    /// Parameters for encoding a complete LDAPMessage SearchRequest (RFC 4511 §4.5.1).
    /// Field names are distinct from <c>LdapSearchConfig</c> so copy-and-update inference stays unambiguous.
    type internal SearchRequestToEncode =
        { messageId : int32
          baseObject : string
          searchScopeByte : byte
          derefAliases : byte
          sizeLimit : int32
          timeLimit : int32
          typesOnly : bool
          searchFilter : string
          attributeNames : string array }


    ///
    /// <summary>
    /// Represents an authenticated LDAP session returned by the Fauli adapter.
    /// Wraps the underlying <c>NetworkStream</c> and owns the message ID counter
    /// used for LDAPv3 message correlation. The mutable counter is encapsulated
    /// here — the domain layer never sees mutation.
    /// </summary>
    ///
    type AuthenticatedLdapSession =
        { stream : System.IO.Stream
          mutable messageId : int32
          boundAs : string option
          authenticationMethod: AuthenticationMethod  }

    ///
    /// Create a new session with the given stream and starting message ID.
    /// When called, nextMessageId is 2 (1 is for the SASL bind).
    ///
    module AuthenticatedLdapSession =

        let create (stream : System.IO.Stream) (nextMessageId : int) authMethod : AuthenticatedLdapSession =
            { stream = stream
              messageId = nextMessageId
              boundAs = None
              authenticationMethod = authMethod }


        ///
        /// Atomically increment the next message ID and advance the counter.
        let incrementMessageId (session : AuthenticatedLdapSession) : int32 =
            let id = session.messageId
            session.messageId <- id + 1
            id

