module Fiewport.FauliAuth

open System

open Fauli.Domain
open Fiewport.Types


///
/// True when the caller supplied a usable non-whitespace value.
let private hasValue (s : string) : bool =
    not (String.IsNullOrWhiteSpace s)


///
/// Trim; treat null/whitespace-only as empty.
let private normalize (s : string) : string =
    match isNull s with
    | true -> ""
    | false -> s.Trim()


///
/// Both hostname and IP supplied: TCP/SPN use hostname; KDC uses IP.
let private endpointsBoth (hostname : string) (ip : string) : ResolvedLdapEndpoints =
    { connectHost = hostname
      kdcHost = ip
      spnHost = hostname }


///
/// Single non-empty role string used for connect, KDC, and SPN.
let private endpointsSingle (host : string) : ResolvedLdapEndpoints =
    { connectHost = host
      kdcHost = host
      spnHost = host }


///
/// Resolve connectHost + kdcHost + spnHost from the two public string fields.
/// IP-only connectHost yields SPN ldap/<ip>, which AD typically rejects;
/// Fauli then falls through to NetNTLMv2.
let internal resolveLdapEndpoints (hostname : string) (ip : string) : Result<ResolvedLdapEndpoints, LdapWireError> =
    let hostname = normalize hostname
    let ip = normalize ip
    match hasValue hostname, hasValue ip with
    | true, true -> Ok (endpointsBoth hostname ip)
    | true, false -> Ok (endpointsSingle hostname)
    | false, true -> Ok (endpointsSingle ip)
    | false, false -> Error (Unexpected "LDAP endpoint requires ldapHostname and/or ldapIP")


///
/// Map Fiewport's useSsl flag to Fauli's LdapTransport.
let private mapLdapTransport (config : LdapSearchConfig) : LdapTransport =
    match config.useSsl with
    | true  -> LdapTls
    | false -> LdapPlain


///
/// Build a Fauli LdapConnectionConfig from Fiewport's search config.
let private buildLdapConnectionConfig (config : LdapSearchConfig) : LdapConnectionConfig =
    { transport = mapLdapTransport config
      followReferrals = true
      connectTimeout = 10000 }


///
/// Build UserPassword credential once username and password smart-constructors succeed.
let private userPasswordCredential (userName : UserName) (password : Password) : Credential =
    UserPassword (UserNamePassword.create userName password)


///
/// Attach password to a validated user name, or NoCredential on failure.
let private credentialWithPassword (userName : UserName) (passwordText : string) : Credential =
    match Password.create passwordText with
    | Error _ -> NoCredential
    | Ok password -> userPasswordCredential userName password


///
/// Convert Fiewport's LdapCredentials into a Fauli Credential.
/// Empty username or password falls back to NoCredential (boundary validation).
let private buildCredential (creds : LdapCredentials) : Credential =
    match UserName.create creds.username with
    | Error _ -> NoCredential
    | Ok userName -> credentialWithPassword userName creds.password


///
/// Map a successful Fauli Host.create into Ok; any Fauli error becomes Unexpected.
let private hostFromFauli (hostString : string) : Result<Host, LdapWireError> =
    match Host.create hostString with
    | Ok host -> Ok host
    | Error _ -> Error (Unexpected "Invalid LDAP host")


///
/// Build a Fauli Host from a string, returning Error on empty/whitespace input.
let private buildHost (hostString : string) : Result<Host, LdapWireError> =
    match String.IsNullOrWhiteSpace hostString with
    | true -> Error (Unexpected "LDAP host cannot be empty")
    | false -> hostFromFauli hostString


///
/// Map Fauli's AuthError into Fiewport's LdapWireError.
let internal mapAuthError (authError : AuthError) : LdapWireError =
    match authError with
    | ProtocolConnectionFailed -> ConnectionFailed "Failed to connect to LDAP server"
    | ProtocolTimeout -> Timeout "LDAP connection timed out"
    | ProtocolHandshakeFailed -> ConnectionFailed "LDAP protocol handshake failed"
    | ProtocolAuthenticationRejected -> BindFailed "LDAP bind was rejected by the server"
    | KerberosRealmUnreachable -> ConnectionFailed "Kerberos realm could not be reached"
    | KerberosTGTExpired -> BindFailed "Kerberos TGT has expired"
    | KerberosTGTAcquisitionFailed -> BindFailed "Failed to acquire Kerberos TGT"
    | KerberosServiceTicketFailed -> BindFailed "Failed to obtain Kerberos service ticket"
    | KerberosSPNNotFound -> BindFailed "Kerberos SPN not found"
    | KerberosPreauthFailed -> BindFailed "Kerberos pre-authentication failed"
    | KerberosTicketExpired -> BindFailed "Kerberos ticket has expired"
    | KerberosClockSkew -> BindFailed "Kerberos clock skew detected"
    | NtlmChallengeFailed -> BindFailed "NTLM challenge failed"
    | NtlmWrongPassword -> BindFailed "NTLM authentication failed - wrong password"
    | NtlmAccountLocked -> BindFailed "NTLM authentication failed - account locked"
    | NtlmAccountDisabled -> BindFailed "NTLM authentication failed - account disabled"
    | NtlmDomainNotFound -> ConnectionFailed "NTLM domain could not be resolved"
    | NtlmVersionNotSupported -> Unexpected "NTLM version not supported"
    | NoSuitableAuthMethod -> Unexpected "No suitable authentication method available"
    | UnsupportedConnectionType -> Unexpected "Unsupported connection type"
    | UnexpectedError msg -> Unexpected msg
    | CertificateInvalid -> BindFailed "Certificate is invalid"
    | CertificateExpired -> BindFailed "Certificate has expired"
    | CertificateChainUntrusted -> BindFailed "Certificate chain is not trusted"
    | CertificatePrivateKeyMissing -> BindFailed "Certificate private key is missing"
    | CertificateHostNameMismatch -> BindFailed "Certificate host name does not match"
    | OAuthTokenEndpointUnreachable -> ConnectionFailed "OAuth token endpoint could not be reached"
    | SamlIdPUnreachable -> ConnectionFailed "SAML IdP could not be reached"
    | SamlAssertionSignatureInvalid -> BindFailed "SAML assertion signature is invalid"
    | _ -> BindFailed "Out of scope Error"


///
/// Continue a Result railway with a named success step (bind lives here only).
let private continueAfter (onOk : 'a -> Result<'b, LdapWireError>) (input : Result<'a, LdapWireError>) : Result<'b, LdapWireError> =
    match input with
    | Error e -> Error e
    | Ok value -> onOk value


///
/// Pair resolved string endpoints with a Fauli Host for the connect role.
let private withConnectHost (endpoints : ResolvedLdapEndpoints) : Result<ResolvedLdapEndpoints * Host, LdapWireError> =
    match buildHost endpoints.connectHost with
    | Error e -> Error e
    | Ok connectHost -> Ok (endpoints, connectHost)


///
/// Add the KDC Host to the partially built host set.
let private withKdcHost (endpoints : ResolvedLdapEndpoints, connectHost : Host) : Result<ResolvedLdapEndpoints * Host * Host, LdapWireError> =
    match buildHost endpoints.kdcHost with
    | Error e -> Error e
    | Ok kdcHost -> Ok (endpoints, connectHost, kdcHost)


///
/// Add the SPN Host and drop the string endpoints (all Fauli Hosts ready).
let private withSpnHost (endpoints : ResolvedLdapEndpoints, connectHost : Host, kdcHost : Host) : Result<ResolvedFauliHosts, LdapWireError> =
    match buildHost endpoints.spnHost with
    | Error e -> Error e
    | Ok spnHost ->
        Ok
            { connectHost = connectHost
              kdcHost = kdcHost
              spnHost = spnHost }


///
/// Railway step: resolved string endpoints → include connect Host.
let private afterResolveEndpoints (endpointsResult : Result<ResolvedLdapEndpoints, LdapWireError>) : Result<ResolvedLdapEndpoints * Host, LdapWireError> =
    continueAfter withConnectHost endpointsResult


///
/// Railway step: add KDC Host.
let private afterConnectHost (partial : Result<ResolvedLdapEndpoints * Host, LdapWireError>) : Result<ResolvedLdapEndpoints * Host * Host, LdapWireError> =
    continueAfter withKdcHost partial


///
/// Railway step: add SPN Host → ResolvedFauliHosts.
let private afterKdcHost (partial : Result<ResolvedLdapEndpoints * Host * Host, LdapWireError>) : Result<ResolvedFauliHosts, LdapWireError> =
    continueAfter withSpnHost partial


///
/// Build AuthenticationRequest once connection type, credential, and hosts are known.
let private toAuthenticationRequest (connectionType : ConnectionType) (credential : Credential) (hosts : ResolvedFauliHosts) : AuthenticationRequest =
    AuthenticationRequest.create connectionType credential hosts.kdcHost hosts.connectHost hosts.spnHost


///
/// Railway step: Fauli hosts → AuthenticationRequest.
let private afterAllHosts (connectionType : ConnectionType) (credential : Credential) (hostsResult : Result<ResolvedFauliHosts, LdapWireError>) : Result<AuthenticationRequest, LdapWireError> =
    match hostsResult with
    | Error e -> Error e
    | Ok hosts -> Ok (toAuthenticationRequest connectionType credential hosts)


///
/// Build a Fauli AuthenticationRequest from Fiewport config and credentials.
/// connectHost = SPN + LDAP TCP; kdcHost = KDC for AS/TGS; spnHost = SPN hostname.
/// 
let private buildAuthenticationRequest (config : LdapSearchConfig) (creds : LdapCredentials) : Result<AuthenticationRequest, LdapWireError> =
    let connectionType = Ldap (buildLdapConnectionConfig config)
    let credential = buildCredential creds
    
    resolveLdapEndpoints config.ldapHostname config.ldapIP
    |> afterResolveEndpoints
    |> afterConnectHost
    |> afterKdcHost
    |> afterAllHosts connectionType credential


///
/// Extract LdapSession + method from a successful Fauli auth response.
let private sessionFromAuthResponse (response : AuthenticatedResponse) : Result<LdapSession * AuthenticationMethod, LdapWireError> =
    match response.connection with
    | AuthLdap ldapSession -> Ok (ldapSession, response.authenticationMethod)
    | _ -> Error (Unexpected "Fauli returned non-LDAP connection handle")


///
/// Call Fauli.Solver.authenticate and extract the LdapSession and authentication method from
/// the AuthLdap connection handle. All Result/Option handling is encapsulated here.
/// 
let private authenticateWithFauli (request : AuthenticationRequest) : Result<(LdapSession * AuthenticationMethod), LdapWireError> =
    match Fauli.Solver.authenticate request with
    | Error authErr -> Error (mapAuthError authErr)
    | Ok response -> sessionFromAuthResponse response


///
/// Wrap the authenticated LdapSession from Fauli in an AuthenticatedLdapSession.
/// Uses Fauli's NextMessageId (starts at 2 after Kerberos bind, 3 after NTLM) so
/// message IDs remain correlated with the server's expectations.
/// 
let private createSession (ldapSession : LdapSession) (authMethod : AuthenticationMethod) : AuthenticatedLdapSession =
    { stream = ldapSession.Stream
      messageId = ldapSession.NextMessageId
      boundAs = ldapSession.BoundAs
      authenticationMethod = authMethod }


///
/// Railway step: AuthenticationRequest → Fauli session pair.
let private afterBuildRequest (requestResult : Result<AuthenticationRequest, LdapWireError>) : Result<LdapSession * AuthenticationMethod, LdapWireError> =
    continueAfter authenticateWithFauli requestResult


///
/// Railway step: Fauli session pair → AuthenticatedLdapSession.
let private afterFauliAuth (sessionResult : Result<LdapSession * AuthenticationMethod, LdapWireError>) : Result<AuthenticatedLdapSession, LdapWireError> =
    match sessionResult with
    | Error e -> Error e
    | Ok (ldapSession, authMethod) -> Ok (createSession ldapSession authMethod)


///
/// Authenticate against an LDAP server
/// Takes Fiewport's LdapCredentials and LdapSearchConfig, performs Kerberos or
/// NTLM SASL bind, and returns an AuthenticatedLdapSession on success.
/// 
let authenticate (creds : LdapCredentials) (config : LdapSearchConfig) : Result<AuthenticatedLdapSession, LdapWireError> =
    buildAuthenticationRequest config creds
    |> afterBuildRequest
    |> afterFauliAuth
