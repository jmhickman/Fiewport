namespace Fiewport

module SecurityDescriptor =
    open System
    
    open LDAPConstants

    ///
    /// Decode an LDAP SID byte array into its human-readable string form (e.g. "S-1-5-21-...").
    ///
    /// Per Microsoft's SID binary layout (MS-DTYP §2.4):
    ///   Offset  Size  Field
    ///   0       1     Revision (typically 1)
    ///   1       1     SubAuthority count
    ///   2       6     Identifier Authority (big-endian, little-endian byte at offset 7 is masked)
    ///   8       4×N   SubAuthorities (each a little-endian DWORD)
    ///
    /// The string representation is: S-Revision-IdentifierAuthority-SubAuthority1-SubAuthority2-...
    ///
    /// Identifier Authority is assembled from its 6 big-endian bytes into a single integer;
    /// the low byte (offset 7) is masked with 0xFF to avoid sign-extension from int32 promotion.
    /// SubAuthorities are read as little-endian uint32 values starting at offset 8.
    /// 
    let internal decodeSidFromBytes bytes =
        match Array.length bytes with
        | len when len < 8 ->
            "INVALID SID"
        | _ ->
            let revision = int bytes[0]
            let subAuthCount = int bytes[1]
            let authority =
                int64 bytes[2] <<< 32 |||
                int64 bytes[3] <<< 24 |||
                int64 bytes[4] <<< 16 |||
                int64 bytes[5] <<< 8 |||
                int64 bytes[6] |||
                int64 bytes[7] &&& 0xFFL
                |> int32

            let subAuthorities =
                [for i in 0 .. subAuthCount - 1 do
                    let offset = 8 + (i * 4)
                    if offset + 4 <= Array.length bytes then
                        yield sprintf "%u" (BitConverter.ToUInt32(bytes, offset))]

            match subAuthorities with
            | [] -> $"""S-{revision}-{authority}"""
            | _ -> $"""S-{revision}-{authority}-{String.concat "-" subAuthorities}"""


    let private lookupWellKnownSid sid =
        wellKnownSids.TryFind sid


    let private lookupNetworkSid (sid: string) =
        sid.Split '-'
        |> Array.last
        |> networkSids.TryFind


    /// Resolve a SID string to a human-readable name.
    /// Checks well-known SIDs first, then network SIDs by RID, falls back to raw SID.
    let private matchKnownSids sid =
        match lookupWellKnownSid sid, lookupNetworkSid sid with
        | Some name, _ -> name
        | _, Some name -> name
        | _ -> sid


    let private getAccessFlags accessMask =
        activeDirectoryRightsList
        |> List.filter (fun e -> accessMask &&& int e = int e)
        |> List.map (fun e -> e.ToString())
        |> String.concat ", "


    ///
    /// Compute where the SID begins inside an ACE.
    /// Standard ACEs: SID starts at offset + 8.
    /// Object ACEs: 8-byte header + 4-byte AceFlags DWORD, then optional GUIDs (16 bytes each), then SID.
    /// 
    let private computeSidOffset (bytes: byte array) curOffset =
        let aceType = bytes.[curOffset]
        match aceType with
        | t when t = accessAllowedObjectAce || t = accessDeniedObjectAce ->
            let aceFlagsOffset = curOffset + 8
            let objFlags = BitConverter.ToInt32(bytes, aceFlagsOffset)
            let addGuidIfPresent flag acc =
                match objFlags &&& flag <> 0 with
                | true -> acc + 16
                | false -> acc
            let extraBytes =
                0 |> addGuidIfPresent aceObjectTypePresent |> addGuidIfPresent aceInheritedObjectTypePresent
            aceFlagsOffset + 4 + extraBytes
        | _ ->
            curOffset + 8


    /// Parse a single ACE entry: extract SID string and access mask.
    let private parseAceEntry bytes curOffset aceSize =
        let sidOffset = computeSidOffset bytes curOffset
        let sid = decodeSidFromBytes (Array.sub bytes sidOffset (aceSize - (sidOffset - curOffset)))
        let accessMask = BitConverter.ToInt32(bytes, curOffset + 4)
        sid, accessMask


    let private readAceSize (bytes: byte array) offset =
        int (BitConverter.ToUInt16(bytes, offset + 2))


    let private getNextAceOffset curOffset aceSize =
        curOffset + (aceSize &&& ~~~3)


    let private formatAceEntry sid accessMask =
        $"{matchKnownSids sid}--{getAccessFlags accessMask}"


    /// Process one ACE: parse, format, and advance to the next.
    let private processAce bytes acc i offset aceCount =
        let aceSize = readAceSize bytes offset
        let formatted = parseAceEntry bytes offset aceSize ||> formatAceEntry
        formatted :: acc, i + 1, getNextAceOffset offset aceSize

    /// Walk all ACEs in the ACL, accumulating formatted permission strings.
    let private parseAceList bytes aceCount aclStart =
        let rec loop acc i offset =
            match i >= aceCount with
            | true -> acc
            | false ->
                let acc, i, offset = processAce bytes acc i offset aceCount
                loop acc i offset
        loop [] 0 aclStart

    ///
    /// Decode an NT Security Descriptor byte array into a list of human-readable
    /// permission strings in the form "Principal--Flags".
    ///
    /// Cross-platform security descriptor + ACL parser.
    /// SD header: Revision(1) + Byte2(1) + Control(2) + Owner(4) + Group(4) + SACL(4) + DACL(4) = 20 bytes
    /// ACL header: AclRevision(1) + Unused(1) + Size(2) + AceCount(2) + Unused(2) = 8 bytes
    /// 
    let internal decodeNtSecurityDescriptor bytes =
        let daclOffset = BitConverter.ToInt32(bytes, 16)
        match daclOffset = 0 with
        | true -> []
        | false ->
            let aceCount = int (BitConverter.ToUInt16(bytes, daclOffset + 4))
            let aclStart = daclOffset + 8
            parseAceList bytes aceCount aclStart
