namespace Fiewport.Tests

module SerializerTests =

    open System
    open System.IO
    open Expecto
    open Fiewport
    open Fiewport.Types

    // The serializer writes to CWD with filenames derived from ldapDN + searchType + config hash.
    // Each test uses a unique config to avoid file collisions, then cleans up after.

    let private originalCwd = Directory.GetCurrentDirectory()

    let private makeConfig (suffix: string) : LdapSearchConfig =
        { TestData.defaultLdapDetails with ldapDN = $"DC=fiewport-test-{suffix},DC=local" }

    // Config hash is structural (F# records override GetHashCode).
    // Two configs with identical fields → same hash. Different fields → different hash.
    let private configHash (cfg: LdapSearchConfig) =
        cfg.GetHashCode() |> abs |> sprintf "%06X"

    let private fileName (cfg: LdapSearchConfig) (searchType: LDAPSearchType) =
        $"{cfg.ldapDN}-{searchType}-{configHash cfg}-lcache.bin"

    let private fullFileName (cfg: LdapSearchConfig) (searchType: LDAPSearchType) =
        Path.Combine(originalCwd, fileName cfg searchType)

    let private cleanupFiles (configs: LdapSearchConfig list) (searchTypes: LDAPSearchType list) =
        for cfg in configs do
            for st in searchTypes do
                let f = fullFileName cfg st
                if File.Exists f then
                    try File.Delete(f) with _ -> ()

    // ── Round-trip tests ─────────────────────────────────────────────

    let ``serialize and deserialize round-trips a single result`` () =
        let suffix = Guid.NewGuid().ToString("N")
        let cfg = makeConfig suffix
        try
            let result = TestData.mkResult LDAPSearchType.GetUsers cfg (TestData.mkMap [
                "cn", ["Administrator"]
                "sAMAccountName", ["Administrator"] ])
            let returned = Serializer.serializeToDisk [result]

            Expect.equal returned.Length 1 "serialize returns input"

            let file = fullFileName cfg LDAPSearchType.GetUsers
            Expect.isTrue (File.Exists file) "file created in CWD"

            let deserialized = Serializer.deserializeFromDisk file

            Expect.equal deserialized.Length 1 "one result restored"
            Expect.equal deserialized.[0].searchType LDAPSearchType.GetUsers "searchType preserved"
            Expect.equal deserialized.[0].searchConfig.ldapHost cfg.ldapHost "config preserved"
            Expect.equal (List.length deserialized.[0].ldapData) 1 "data count preserved"
        finally
            cleanupFiles [cfg] [LDAPSearchType.GetUsers]

    let ``serialize and deserialize round-trips multiple results`` () =
        let suffix = Guid.NewGuid().ToString("N")
        let cfg = makeConfig suffix
        try
            let r1 = TestData.mkResult LDAPSearchType.GetUsers cfg (TestData.mkMap [ "cn", ["User1"] ])
            let r2 = TestData.mkResult LDAPSearchType.GetUsers cfg (TestData.mkMap [ "cn", ["User2"] ])
            let r3 = TestData.mkResult LDAPSearchType.GetComputers cfg (TestData.mkMap [ "cn", ["PC1"] ])
            Serializer.serializeToDisk [r1; r2; r3] |> ignore

            let usersFile = fullFileName cfg LDAPSearchType.GetUsers
            let computersFile = fullFileName cfg LDAPSearchType.GetComputers

            Expect.isTrue (File.Exists usersFile) "users file created"
            Expect.isTrue (File.Exists computersFile) "computers file created"

            let users = Serializer.deserializeFromDisk usersFile
            let computers = Serializer.deserializeFromDisk computersFile

            Expect.equal (users.Length + computers.Length) 3 "all three results restored"
        finally
            cleanupFiles [cfg] [LDAPSearchType.GetUsers; LDAPSearchType.GetComputers]

    let ``round-trip preserves ldapData content`` () =
        let suffix = Guid.NewGuid().ToString("N")
        let cfg = makeConfig suffix
        try
            let originalMap = TestData.mkMap [
                "cn", ["Administrator"]
                "adminCount", ["1"]
                "useraccountcontrol", ["66048"] ]
            let result = TestData.mkResult LDAPSearchType.GetUsers cfg originalMap
            Serializer.serializeToDisk [result] |> ignore

            let file = fullFileName cfg LDAPSearchType.GetUsers
            let deserialized = Serializer.deserializeFromDisk file
            let restoredData = deserialized.[0].ldapData.[0]

            Expect.equal restoredData.Count originalMap.Count "same attribute count"
            for key in originalMap.Keys do
                Expect.isTrue (Map.containsKey key restoredData) $"key {key} preserved"
                Expect.equal restoredData.[key] originalMap.[key] $"values for {key} match"
        finally
            cleanupFiles [cfg] [LDAPSearchType.GetUsers]

    let ``round-trip preserves error results`` () =
        let suffix = Guid.NewGuid().ToString("N")
        let cfg = makeConfig suffix
        try
            let errResult = TestData.mkErrorResult cfg "connection refused"
            Serializer.serializeToDisk [errResult] |> ignore

            let file = fullFileName cfg LDAPSearchType.GetUsers
            let deserialized = Serializer.deserializeFromDisk file

            Expect.equal deserialized.Length 1 "error result preserved"
            match deserialized.[0].ldapSearcherError with
            | Some err -> Expect.stringContains err.message "connection refused" "error message preserved"
            | None -> Expect.isTrue false "expected error to be preserved"
        finally
            cleanupFiles [cfg] [LDAPSearchType.GetUsers]

    // ── Filename behavior ────────────────────────────────────────────

    let ``identical configs group into one file`` () =
        let suffix = Guid.NewGuid().ToString("N")
        let cfg = makeConfig suffix
        try
            let r1 = TestData.mkResult LDAPSearchType.GetUsers cfg (TestData.mkMap [ "cn", ["User1"] ])
            let r2 = TestData.mkResult LDAPSearchType.GetUsers cfg (TestData.mkMap [ "cn", ["User2"] ])
            Serializer.serializeToDisk [r1; r2] |> ignore

            let file = fullFileName cfg LDAPSearchType.GetUsers
            Expect.isTrue (File.Exists file) "single file for identical configs"

            let deserialized = Serializer.deserializeFromDisk file
            Expect.equal deserialized.Length 2 "both results in one file"
        finally
            cleanupFiles [cfg] [LDAPSearchType.GetUsers]

    let ``different searchType produces separate files`` () =
        let suffix = Guid.NewGuid().ToString("N")
        let cfg = makeConfig suffix
        try
            let r1 = TestData.mkResult LDAPSearchType.GetUsers cfg (TestData.mkMap [ "cn", ["User1"] ])
            let r2 = TestData.mkResult LDAPSearchType.GetComputers cfg (TestData.mkMap [ "cn", ["PC1"] ])
            Serializer.serializeToDisk [r1; r2] |> ignore

            Expect.isTrue (File.Exists (fullFileName cfg LDAPSearchType.GetUsers)) "users file"
            Expect.isTrue (File.Exists (fullFileName cfg LDAPSearchType.GetComputers)) "computers file"
        finally
            cleanupFiles [cfg] [LDAPSearchType.GetUsers; LDAPSearchType.GetComputers]

    let ``different ldapDN produces separate files`` () =
        let suffix1 = Guid.NewGuid().ToString("N")
        let suffix2 = Guid.NewGuid().ToString("N")
        let cfg1 = makeConfig suffix1
        let cfg2 = makeConfig suffix2
        try
            let r1 = TestData.mkResult LDAPSearchType.GetUsers cfg1 (TestData.mkMap [ "cn", ["User1"] ])
            let r2 = TestData.mkResult LDAPSearchType.GetUsers cfg2 (TestData.mkMap [ "cn", ["User2"] ])
            Serializer.serializeToDisk [r1; r2] |> ignore

            Expect.isTrue (File.Exists (fullFileName cfg1 LDAPSearchType.GetUsers)) "first file"
            Expect.isTrue (File.Exists (fullFileName cfg2 LDAPSearchType.GetUsers)) "second file"
        finally
            cleanupFiles [cfg1; cfg2] [LDAPSearchType.GetUsers]

    let ``different ldapHost produces separate files`` () =
        let suffix = Guid.NewGuid().ToString("N")
        let cfg1 = makeConfig suffix
        let cfg2 = { cfg1 with ldapHost = "other-host" }
        try
            let r1 = TestData.mkResult LDAPSearchType.GetUsers cfg1 (TestData.mkMap [ "cn", ["User1"] ])
            let r2 = TestData.mkResult LDAPSearchType.GetUsers cfg2 (TestData.mkMap [ "cn", ["User2"] ])
            Serializer.serializeToDisk [r1; r2] |> ignore

            // Same ldapDN + searchType, but different ldapHost → separate files
            Expect.isTrue (File.Exists (fullFileName cfg1 LDAPSearchType.GetUsers)) "first config file"
            Expect.isTrue (File.Exists (fullFileName cfg2 LDAPSearchType.GetUsers)) "second config file"
            Expect.notEqual (fullFileName cfg1 LDAPSearchType.GetUsers) (fullFileName cfg2 LDAPSearchType.GetUsers) "filenames differ"
        finally
            cleanupFiles [cfg1; cfg2] [LDAPSearchType.GetUsers]

    let ``serializeToDisk pass-throughs input for pipeline use`` () =
        let suffix = Guid.NewGuid().ToString("N")
        let cfg = makeConfig suffix
        try
            let results = [TestData.mkResult LDAPSearchType.GetUsers cfg (TestData.mkMap [ "cn", ["User1"] ])]
            let returned = Serializer.serializeToDisk results

            Expect.equal returned results "returns input list"
        finally
            cleanupFiles [cfg] [LDAPSearchType.GetUsers]

    // ── Empty / edge cases ───────────────────────────────────────────

    let ``serialize empty list does not crash`` () =
        let returned = Serializer.serializeToDisk []
        Expect.equal returned [] "empty list returned"

    let ``deserialize non-existent file throws`` () =
        Expect.throws (fun () -> Serializer.deserializeFromDisk "no-such-file.bin" |> ignore) "missing file throws"

    let serializerTests =
        testList "Serializer" [
            testCase "serialize and deserialize round-trips a single result" ``serialize and deserialize round-trips a single result``
            testCase "serialize and deserialize round-trips multiple results" ``serialize and deserialize round-trips multiple results``
            testCase "round-trip preserves ldapData content" ``round-trip preserves ldapData content``
            testCase "round-trip preserves error results" ``round-trip preserves error results``
            testCase "identical configs group into one file" ``identical configs group into one file``
            testCase "different searchType produces separate files" ``different searchType produces separate files``
            testCase "different ldapDN produces separate files" ``different ldapDN produces separate files``
            testCase "different ldapHost produces separate files" ``different ldapHost produces separate files``
            testCase "serializeToDisk returns the original results" ``serializeToDisk pass-throughs input for pipeline use``
            testCase "serialize empty list does not crash" ``serialize empty list does not crash``
            testCase "deserialize non-existent file throws" ``deserialize non-existent file throws`` ]
