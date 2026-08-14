namespace Fiewport

[<AutoOpen>]
module Types =

    
    open MessagePack

    /// <summary>Search scope for LDAP queries.</summary>
    type SearchScope =
        | Base
        | OneLevel
        | Subtree

    ///
    /// <summary>Representation of unboxed data from an LDAP query.</summary>
    /// <remarks>Some of these datatypes are speculation and aren't confirmed in real results.
    /// I have access to a limited AD that is very simplistic, so verifying all of these is likely
    /// impossible for me alone.
    /// </remarks>
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
    
    
    ///
    /// <summary>Represents a single LDAP entry as a map of attribute names to decoded string values.</summary>
    ///
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
          [<Key(3)>]ldapData: LDAPEntryData list }

    
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
    /// <summary>
    /// Represents an authenticated LDAP session returned by the Fauli adapter.
    /// Wraps the underlying <c>NetworkStream</c> and owns the message ID counter
    /// used for LDAPv3 message correlation. The mutable counter is encapsulated
    /// here — the domain layer never sees mutation.
    /// </summary>
    ///
    type AuthenticatedLdapSession =
        { Stream : System.IO.Stream
          mutable messageId : int32
          BoundAs : string option }

    module AuthenticatedLdapSession =
        /// Create a new session with the given stream and starting message ID.
        /// When called, nextMessageId is 2 (1 is for the SASL bind).
        let create (stream : System.IO.Stream) (nextMessageId : int) : AuthenticatedLdapSession =
            { Stream = stream
              messageId = nextMessageId
              BoundAs = None }

        /// Atomically allocate the next message ID and advance the counter.
        let allocateMessageId (session : AuthenticatedLdapSession) : int32 =
            let id = session.messageId
            session.messageId <- id + 1
            id




