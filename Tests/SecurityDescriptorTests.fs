namespace Fiewport.Tests

module SecurityDescriptorTests =

    open System
    open Expecto
    open Fiewport

    // Helper: copy source array into destination starting at destIndex
    let private arrayCopyTo (src: byte[]) (dst: byte[]) (destIndex: int) =
        for i in 0 .. src.Length - 1 do
            dst.[destIndex + i] <- src.[i]

    // Helper: build a minimal SID byte array
    let private buildSidBytes (authority: int) (subAuthorities: int list) =
        let subAuthCount = List.length subAuthorities
        let size = 8 + (subAuthCount * 4)
        let bytes = Array.zeroCreate<byte> size
        bytes.[0] <- 1uy
        bytes.[1] <- byte subAuthCount
        bytes.[2] <- byte (authority >>> 32)
        bytes.[3] <- byte (authority >>> 24)
        bytes.[4] <- byte (authority >>> 16)
        bytes.[5] <- byte (authority >>> 8)
        bytes.[6] <- byte authority
        bytes.[7] <- byte (authority &&& 0xFF)
        subAuthorities |> List.iteri (fun i v ->
            let b = BitConverter.GetBytes(uint32 v)
            for j in 0 .. 3 do bytes.[8 + i * 4 + j] <- b.[j])
        bytes

    // Well-known SIDs for testing
    let private sidLocalSystem = buildSidBytes 5 [18]
    let private sidAuthUsers = buildSidBytes 5 [11]
    let private sidEveryone = buildSidBytes 1 []
    let private sidAdmins = buildSidBytes 5 [32; 544]
    let private sidSelf = buildSidBytes 5 [10]

    // Helper: build a standard ACE (ACCESS_ALLOWED_ACE type = 0x00)
    let private buildStandardAce (accessMask: int) (sid: byte[]) =
        let aceSize = 8 + Array.length sid
        let bytes = Array.zeroCreate<byte> aceSize
        bytes.[0] <- 0x00uy
        bytes.[1] <- 0x00uy
        let sizeBytes = BitConverter.GetBytes(uint16 aceSize)
        arrayCopyTo sizeBytes bytes 2
        let maskBytes = BitConverter.GetBytes(accessMask)
        arrayCopyTo maskBytes bytes 4
        arrayCopyTo sid bytes 8
        bytes

    // Helper: build an Object ACE (ACCESS_ALLOWED_OBJECT_ACE type = 0x05)
    let private buildObjectAce (accessMask: int) (sid: byte[])
                               (objectTypePresent: bool) (objectType: byte[] option)
                               (inheritedTypePresent: bool) (inheritedType: byte[] option) =
        let guidSize =
            (if objectTypePresent then 16 else 0) +
            (if inheritedTypePresent then 16 else 0)
        let aceSize = 8 + 4 + guidSize + Array.length sid
        let bytes = Array.zeroCreate<byte> aceSize
        bytes.[0] <- 0x05uy
        bytes.[1] <- 0x00uy
        let sizeBytes = BitConverter.GetBytes(uint16 aceSize)
        arrayCopyTo sizeBytes bytes 2
        let maskBytes = BitConverter.GetBytes(accessMask)
        arrayCopyTo maskBytes bytes 4
        let objFlags =
            (if objectTypePresent then 0x01 else 0x00) |||
            (if inheritedTypePresent then 0x02 else 0x00)
        let flagBytes = BitConverter.GetBytes(objFlags)
        arrayCopyTo flagBytes bytes 8
        let mutable offset = 12
        if objectTypePresent then
            arrayCopyTo objectType.Value bytes offset
            offset <- offset + 16
        if inheritedTypePresent then
            arrayCopyTo inheritedType.Value bytes offset
            offset <- offset + 16
        arrayCopyTo sid bytes offset
        bytes

    // Helper: build a minimal ACL with given ACEs
    let private buildAcl (aces: byte[] list) =
        let aceDataSize = aces |> List.sumBy Array.length
        let aclSize = 8 + aceDataSize
        let bytes = Array.zeroCreate<byte> aclSize
        bytes.[0] <- 0x04uy
        let sizeBytes = BitConverter.GetBytes(uint16 aclSize)
        arrayCopyTo sizeBytes bytes 2
        let countBytes = BitConverter.GetBytes(uint16 (List.length aces))
        arrayCopyTo countBytes bytes 4
        let mutable offset = 8
        aces |> List.iter (fun ace ->
            arrayCopyTo ace bytes offset
            offset <- offset + Array.length ace)
        bytes

    // Helper: build a minimal Security Descriptor with given DACL
    let private buildSecurityDescriptor (dacl: byte[] option) =
        let sdHeaderSize = 20
        let daclSize = match dacl with Some a -> Array.length a | None -> 0
        let bytes = Array.zeroCreate<byte> (sdHeaderSize + daclSize)
        bytes.[0] <- 0x01uy
        bytes.[1] <- 0x00uy
        let ctrlBytes = BitConverter.GetBytes(uint16 0x0004)
        arrayCopyTo ctrlBytes bytes 2
        match dacl with
        | Some a ->
            let offsetBytes = BitConverter.GetBytes(sdHeaderSize)
            arrayCopyTo offsetBytes bytes 16
            arrayCopyTo a bytes sdHeaderSize
        | None -> ()
        bytes

    let securityDescriptorTests =
        testList "SecurityDescriptor" [
            // --- SID decoding tests ---
            test "decodeSidFromBytes: Local System S-1-5-18" {
                let sid = sidLocalSystem |> SecurityDescriptor.decodeSidFromBytes
                Expect.equal sid "S-1-5-18" "should decode to S-1-5-18"
            }

            test "decodeSidFromBytes: Authenticated Users S-1-5-11" {
                let sid = sidAuthUsers |> SecurityDescriptor.decodeSidFromBytes
                Expect.equal sid "S-1-5-11" "should decode to S-1-5-11"
            }

            test "decodeSidFromBytes: Administrators S-1-5-32-544" {
                let sid = sidAdmins |> SecurityDescriptor.decodeSidFromBytes
                Expect.equal sid "S-1-5-32-544" "should decode to S-1-5-32-544"
            }

            test "decodeSidFromBytes: Everyone S-1-1" {
                let sid = sidEveryone |> SecurityDescriptor.decodeSidFromBytes
                Expect.equal sid "S-1-1" "should decode to S-1-1"
            }

            test "decodeSidFromBytes: too short returns INVALID SID" {
                let sid = [| 1uy; 1uy |] |> SecurityDescriptor.decodeSidFromBytes
                Expect.equal sid "INVALID SID" "should return INVALID SID for short bytes"
            }

            // --- Standard ACE tests ---
            test "decodeNtSecurityDescriptor: single standard ACE" {
                let ace = buildStandardAce 0x0013019F sidLocalSystem
                let acl = buildAcl [ace]
                let sd = buildSecurityDescriptor (Some acl)
                let result = SecurityDescriptor.decodeNtSecurityDescriptor sd
                Expect.equal (List.length result) 1 "should have 1 ACE entry"
                Expect.stringContains (List.head result) "Local System" "should resolve Local System"
            }

            test "decodeNtSecurityDescriptor: multiple standard ACEs" {
                let ace1 = buildStandardAce 0x0013019F sidLocalSystem
                let ace2 = buildStandardAce 0x000200A4 sidAuthUsers
                let acl = buildAcl [ace1; ace2]
                let sd = buildSecurityDescriptor (Some acl)
                let result = SecurityDescriptor.decodeNtSecurityDescriptor sd
                Expect.equal (List.length result) 2 "should have 2 ACE entries"
                // Result is reversed (cons-to-front), so head is last ACE
                Expect.stringContains (List.head result) "Authenticated Users" "last ACE is Authenticated Users"
                Expect.stringContains (List.last result) "Local System" "first ACE is Local System"
            }

            test "decodeNtSecurityDescriptor: empty DACL returns empty list" {
                let sd = buildSecurityDescriptor None
                let result = SecurityDescriptor.decodeNtSecurityDescriptor sd
                Expect.isEmpty result "should return empty list"
            }

            test "decodeNtSecurityDescriptor: too short SD returns empty list" {
                let sd = [| 1uy; 2uy |]
                let result = SecurityDescriptor.decodeNtSecurityDescriptor sd
                Expect.isEmpty result "should return empty list for short SD"
            }

            // --- Object ACE tests (the actual fix) ---
            test "decodeNtSecurityDescriptor: Object ACE with ObjectType present" {
                let objectType = Array.zeroCreate<byte> 16
                let ace =
                    buildObjectAce 0x00000100 sidEveryone
                        true (Some objectType) false None
                let acl = buildAcl [ace]
                let sd = buildSecurityDescriptor (Some acl)
                let result = SecurityDescriptor.decodeNtSecurityDescriptor sd
                Expect.equal (List.length result) 1 "should have 1 ACE entry"
                Expect.stringContains (List.head result) "World" "should resolve S-1-1 to World"
                Expect.stringContains (List.head result) "ExtendedRight" "should contain ExtendedRight"
            }

            test "decodeNtSecurityDescriptor: Object ACE with both GUIDs present" {
                let objectType = Array.zeroCreate<byte> 16
                let inheritedType = Array.zeroCreate<byte> 16
                let ace =
                    buildObjectAce 0x00000130 sidSelf
                        true (Some objectType) true (Some inheritedType)
                let acl = buildAcl [ace]
                let sd = buildSecurityDescriptor (Some acl)
                let result = SecurityDescriptor.decodeNtSecurityDescriptor sd
                Expect.equal (List.length result) 1 "should have 1 ACE entry"
                Expect.stringContains (List.head result) "Self" "should resolve Self"
            }

            test "decodeNtSecurityDescriptor: mixed standard and Object ACEs" {
                let ace1 = buildStandardAce 0x0013019F sidLocalSystem
                let ace2 = buildStandardAce 0x000200A4 sidAuthUsers
                let ace3 = buildStandardAce 0x001F01FF sidAdmins
                let objectType = Array.zeroCreate<byte> 16
                let ace4 =
                    buildObjectAce 0x00000100 sidEveryone
                        true (Some objectType) false None
                let ace5 =
                    buildObjectAce 0x00000130 sidSelf
                        true (Some objectType) false None
                let acl = buildAcl [ace1; ace2; ace3; ace4; ace5]
                let sd = buildSecurityDescriptor (Some acl)
                let result = SecurityDescriptor.decodeNtSecurityDescriptor sd
                Expect.equal (List.length result) 5 "should have 5 ACE entries"
                // Result is reversed (cons-to-front), so head = last ACE
                Expect.stringContains (List.item 0 result) "Self" "ACE 5 (head): Self"
                Expect.stringContains (List.item 1 result) "World" "ACE 4: S-1-1 resolved to World"
                Expect.stringContains (List.item 2 result) "Administrator" "ACE 3: Administrators"
                Expect.stringContains (List.item 3 result) "Authenticated Users" "ACE 2: Authenticated Users"
                Expect.stringContains (List.item 4 result) "Local System" "ACE 1 (last): Local System"
            }

            test "decodeNtSecurityDescriptor: Object ACE without GUIDs" {
                let ace =
                    buildObjectAce 0x00000100 sidSelf
                        false None false None
                let acl = buildAcl [ace]
                let sd = buildSecurityDescriptor (Some acl)
                let result = SecurityDescriptor.decodeNtSecurityDescriptor sd
                Expect.equal (List.length result) 1 "should have 1 ACE entry"
                Expect.stringContains (List.head result) "Self" "should resolve Self"
            }
        ]
