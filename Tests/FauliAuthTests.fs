namespace Fiewport.Tests

module FauliAuthTests =

    open System.IO
    open Expecto
    open Fiewport
    open Fiewport.Types
    open Fauli.Domain

    let private sampleConfig host =
        { properties = [||]
          filter = ""
          ldapDN = "DC=example,DC=com"
          scope = Subtree
          ldapHostname = host
          ldapIP = ""
          ldapPort = 389
          useSsl = false }

    type private ErrorKind =
        | KindConnection
        | KindBind
        | KindTimeout
        | KindUnexpected

    let private kindOf (err: LdapWireError) =
        match err with
        | ConnectionFailed _ -> KindConnection
        | BindFailed _ -> KindBind
        | Timeout _ -> KindTimeout
        | Unexpected _ -> KindUnexpected
        | SearchFailed _ -> failtest "auth errors must not map to SearchFailed"
        | BerDecodeError _ -> failtest "auth errors must not map to BerDecodeError"

    let fauliAuthTests =
        testList "FauliAuth"
            [ testList "resolveLdapEndpoints"
                  [ test "both hostname and IP: connect=hostname, kdc=IP, spn=hostname" {
                        match FauliAuth.resolveLdapEndpoints "dc.ad-lab.local" "192.168.10.38" with
                        | Ok e ->
                            Expect.equal e.connectHost "dc.ad-lab.local" "TCP connect host"
                            Expect.equal e.kdcHost "192.168.10.38" "KDC host"
                            Expect.equal e.spnHost "dc.ad-lab.local" "SPN hostname"
                        | Error e -> failtest $"unexpected error: {e}"
                    }

                    test "hostname only: all roles use hostname" {
                        match FauliAuth.resolveLdapEndpoints "dc.ad-lab.local" "" with
                        | Ok e ->
                            Expect.equal e.connectHost "dc.ad-lab.local" "connect"
                            Expect.equal e.kdcHost "dc.ad-lab.local" "kdc"
                            Expect.equal e.spnHost "dc.ad-lab.local" "spn"
                        | Error e -> failtest $"unexpected error: {e}"
                    }

                    test "IP only: all roles use IP (Kerberos SPN will fail → NTLM)" {
                        match FauliAuth.resolveLdapEndpoints "" "192.168.10.38" with
                        | Ok e ->
                            Expect.equal e.connectHost "192.168.10.38" "connect"
                            Expect.equal e.kdcHost "192.168.10.38" "kdc"
                            Expect.equal e.spnHost "192.168.10.38" "spn"
                        | Error e -> failtest $"unexpected error: {e}"
                    }

                    test "whitespace-only values are treated as absent" {
                        match FauliAuth.resolveLdapEndpoints "  " "\t" with
                        | Error (Unexpected msg) ->
                            Expect.stringContains msg "ldapHostname" "mentions fields"
                        | other -> failtest $"expected Unexpected, got {other}"
                    }

                    test "neither hostname nor IP fails locally" {
                        match FauliAuth.resolveLdapEndpoints "" "" with
                        | Error (Unexpected _) -> ()
                        | other -> failtest $"expected Unexpected, got {other}"
                    } ]

              testList "AuthenticatedLdapSession"
                  [ test "allocateMessageId returns the start id then increments" {
                        use ms = new MemoryStream()
                        // Fauli NTLM bind consumes ids 1 and 2 → next is 3
                        let session = AuthenticatedLdapSession.create ms 3 Kerberos
                        Expect.equal (AuthenticatedLdapSession.incrementMessageId session) 3 "first"
                        Expect.equal (AuthenticatedLdapSession.incrementMessageId session) 4 "second"
                        Expect.equal (AuthenticatedLdapSession.incrementMessageId session) 5 "third"
                        Expect.equal session.messageId 6 "counter advanced"
                    }

                    test "create preserves the stream reference used for subsequent wire I/O" {
                        use ms = new MemoryStream()
                        let session = AuthenticatedLdapSession.create ms 2 Kerberos
                        Expect.isTrue (obj.ReferenceEquals(session.stream, ms)) "same stream"
                    } ]

              testList "mapAuthError"
                  [ test "maps every AuthError case into a non-wire LdapWireError kind" {
                        let cases: (AuthError * ErrorKind) list =
                            [ ProtocolConnectionFailed, KindConnection
                              ProtocolTimeout, KindTimeout
                              ProtocolHandshakeFailed, KindConnection
                              ProtocolAuthenticationRejected, KindBind
                              KerberosRealmUnreachable, KindConnection
                              KerberosTGTExpired, KindBind
                              KerberosTGTAcquisitionFailed, KindBind
                              KerberosServiceTicketFailed, KindBind
                              KerberosSPNNotFound, KindBind
                              KerberosPreauthFailed, KindBind
                              KerberosTicketExpired, KindBind
                              KerberosClockSkew, KindBind
                              NtlmChallengeFailed, KindBind
                              NtlmWrongPassword, KindBind
                              NtlmAccountLocked, KindBind
                              NtlmAccountDisabled, KindBind
                              NtlmDomainNotFound, KindConnection
                              NtlmVersionNotSupported, KindUnexpected
                              NoSuitableAuthMethod, KindUnexpected
                              UnsupportedConnectionType, KindUnexpected
                              CertificateInvalid, KindBind
                              CertificateExpired, KindBind
                              CertificateChainUntrusted, KindBind
                              CertificatePrivateKeyMissing, KindBind
                              CertificateHostNameMismatch, KindBind
                              OAuthTokenExpired, KindBind
                              OAuthTokenInvalid, KindBind
                              OAuthTokenEndpointUnreachable, KindConnection
                              OAuthInsufficientScopes, KindBind
                              OAuthClientCredentialsInvalid, KindBind
                              SamlAssertionExpired, KindBind
                              SamlAssertionInvalid, KindBind
                              SamlIdPUnreachable, KindConnection
                              SamlAssertionSignatureInvalid, KindBind
                              UnexpectedError "detail", KindUnexpected ]

                        cases
                        |> List.iter (fun (authErr, expectedKind) ->
                            let mapped = FauliAuth.mapAuthError authErr
                            Expect.equal (kindOf mapped) expectedKind $"{authErr} → {expectedKind}")
                    }

                    test "UnexpectedError preserves the diagnostic message" {
                        match FauliAuth.mapAuthError (UnexpectedError "custom detail") with
                        | Unexpected msg -> Expect.equal msg "custom detail" "message"
                        | other -> failtest $"expected Unexpected, got {other}"
                    }

                    test "NtlmWrongPassword message remains actionable" {
                        match FauliAuth.mapAuthError NtlmWrongPassword with
                        | BindFailed msg ->
                            Expect.stringContains msg "password" "mentions password"
                        | other -> failtest $"expected BindFailed, got {other}"
                    } ]

              testList "authenticate boundary"
                  [ test "empty hostname and IP fails locally with Unexpected" {
                        let result =
                            FauliAuth.authenticate
                                { username = "user"; password = "pass" }
                                (sampleConfig "")
                        match result with
                        | Error (Unexpected msg) ->
                            Expect.stringContains msg "ldap" "mentions ldap endpoint"
                        | other -> failtest $"expected local Unexpected, got {other}"
                    }

                    test "whitespace-only hostname fails locally without attempting connect" {
                        let result =
                            FauliAuth.authenticate
                                { username = "user"; password = "pass" }
                                (sampleConfig "   ")
                        match result with
                        | Error (Unexpected _) -> ()
                        | other -> failtest $"expected local Unexpected, got {other}"
                    } ] ]
