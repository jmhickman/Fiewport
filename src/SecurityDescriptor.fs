namespace Fiewport

module SecurityDescriptor =
    open System
    open LDAPConstants

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
    let internal decodeSidFromBytes (bytes: byte[]) =
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

            $"""S-{revision}-{authority}-{String.concat "-" subAuthorities}"""

    /// Compute the next ACE offset, advancing minimally (4 bytes) for malformed ACEs,
    /// or rounding up to a 4-byte boundary for valid ones.
    let private getNextAceOffset (curOffset: int) (aceSize: int) =
        match aceSize with
        | size when size < 8 -> curOffset + 4
        | size -> curOffset + (size &&& ~~~3)

    /// Attempt to extract a SID and access mask from a valid ACE.
    /// Returns None for malformed ACEs (size < 8) or out-of-bounds SID data.
    let private tryParseAceEntry (bytes: byte[]) (curOffset: int) (aceSize: int) =
        match aceSize with
        | size when size < 8 -> None
        | _ ->
            let sidOffset = curOffset + 8
            let sidSize = aceSize - 8
            match sidOffset + sidSize <= Array.length bytes with
            | false -> None
            | true ->
                let sidBytes = Array.sub bytes sidOffset sidSize
                let sid = decodeSidFromBytes sidBytes
                let accessMask = BitConverter.ToInt32(bytes, curOffset + 4)
                Some (sid, accessMask)

    /// Match a decoded SID string against well-known and network SIDs, returning a
    /// human-readable name when available or the raw SID as a fallback.
    let private matchKnownSids (sid: string) =
        match wellKnownSids.ContainsKey sid with
        | true -> wellKnownSids[sid]
        | false ->
            let lastSubAuth = sid.Split '-' |> Array.last
            match networkSids.ContainsKey lastSubAuth with
            | true -> networkSids[lastSubAuth]
            | false -> sid

    /// Filter the AD rights enumeration by bitmask, returning matching flag names joined by ", ".
    let private getAccessFlags (accessMask: int) =
        activeDirectoryRightsList
        |> List.filter (fun e -> accessMask &&& int e = int e)
        |> List.map (fun e -> e.ToString())
        |> String.concat ", "

    /// Recursively walk ACE entries in an ACL, collecting decoded permission strings.
    let private parseAclEntries (bytes: byte[]) (aceCount: int) (aclStart: int) =
        let rec loop acc i curOffset =
            match i >= aceCount || curOffset + 8 > Array.length bytes with
            | true -> acc
            | false ->
                let aceSize = int (BitConverter.ToUInt16(bytes, curOffset + 2))
                let nextOffset = getNextAceOffset curOffset aceSize
                match tryParseAceEntry bytes curOffset aceSize with
                | None -> loop acc (i + 1) nextOffset
                | Some (sid, accessMask) ->
                    let flags = getAccessFlags accessMask
                    let entry = $"{matchKnownSids sid}--{flags}"
                    loop (entry :: acc) (i + 1) nextOffset
        loop [] 0 aclStart

    /// Decode an NT Security Descriptor byte array into a list of human-readable
    /// permission strings in the form "Principal--Flags".
    ///
    /// Cross-platform security descriptor + ACL parser.
    /// SD header: Revision(1) + Byte2(1) + Control(2) + Owner(4) + Group(4) + SACL(4) + DACL(4) = 20 bytes
    let internal decodeNtSecurityDescriptor (bytes: byte[]) =
        match Array.length bytes with
        | len when len < 20 -> []
        | _ ->
            // Get DACL offset from security descriptor header (offset 16-19)
            let daclOffset = BitConverter.ToInt32(bytes, 16)
            match daclOffset = 0 || daclOffset + 8 > Array.length bytes with
            | true -> []
            | false ->
                // ACL header: AclRevision(1) + Unused(1) + Size(2) + AceCount(2) + Unused(2) = 8 bytes
                let aceCount = int (BitConverter.ToUInt16(bytes, daclOffset + 4))
                let aclStart = daclOffset + 8
                parseAclEntries bytes aceCount aclStart
