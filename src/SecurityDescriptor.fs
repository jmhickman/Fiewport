namespace Fiewport

module SecurityDescriptor =
    open System

    open LDAPConstants


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
                [ for i in 0 .. subAuthCount - 1 do
                    let offset = 8 + (i * 4)
                    if offset + 4 <= Array.length bytes then
                        yield sprintf "%u" (BitConverter.ToUInt32(bytes, offset)) ]

            match subAuthorities with
            | [] -> $"""S-{revision}-{authority}"""
            | _ -> $"""S-{revision}-{authority}-{String.concat "-" subAuthorities}"""


    let private lookupWellKnownSid sid =
        wellKnownSids.TryFind sid


    let private lookupNetworkSid (sid: string) =
        sid.Split '-'
        |> Array.last
        |> networkSids.TryFind


    ///
    /// Resolve a SID string to a human-readable name.
    /// Checks well-known SIDs first, then network SIDs by RID, falls back to raw SID.
    ///
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
    /// Read a 16-byte GUID at offset, if in bounds.
    ///
    let private tryReadGuid (bytes: byte array) offset =
        match offset + 16 <= Array.length bytes with
        | true -> Guid(Array.sub bytes offset 16) |> Some
        | false -> None


    ///
    /// Object ACE layout after the 8-byte ACE header:
    /// Flags DWORD, optional ObjectType GUID, optional InheritedObjectType GUID, then SID.
    /// Returns SID start offset and optional ObjectType.
    ///
    let private objectAceSidOffsetAndType (bytes: byte array) curOffset =
        let flagsOffset = curOffset + 8
        let objFlags = BitConverter.ToInt32(bytes, flagsOffset)
        let afterFlags = flagsOffset + 4

        let objectType, afterObjectType =
            match objFlags &&& aceObjectTypePresent <> 0 with
            | true -> tryReadGuid bytes afterFlags, afterFlags + 16
            | false -> None, afterFlags

        let sidOffset =
            match objFlags &&& aceInheritedObjectTypePresent <> 0 with
            | true -> afterObjectType + 16
            | false -> afterObjectType

        sidOffset, objectType


    ///
    /// Compute where the SID begins inside an ACE, and any ObjectType GUID.
    /// Standard ACEs: SID at offset + 8, no ObjectType.
    ///
    let private computeSidOffsetAndObjectType (bytes: byte array) curOffset =
        let aceType = bytes[curOffset]
        match aceType with
        | t when t = accessAllowedObjectAce || t = accessDeniedObjectAce ->
            objectAceSidOffsetAndType bytes curOffset
        | _ ->
            curOffset + 8, None


    ///
    /// Parse a single ACE: SID, access mask, optional ObjectType GUID, allow vs deny.
    ///
    let private parseAceEntry (bytes: byte array) (curOffset: int) (aceSize: int) =
        let aceType = bytes[curOffset]
        let sidOffset, objectType = computeSidOffsetAndObjectType bytes curOffset
        let sidLength = aceSize - (sidOffset - curOffset)
        let sid =
            match sidLength > 0 with
            | true -> decodeSidFromBytes (Array.sub bytes sidOffset sidLength)
            | false -> "INVALID SID"
        let accessMask = BitConverter.ToInt32(bytes, curOffset + 4)
        let isAllow =
            match aceType with
            | t when t = accessDeniedAce || t = accessDeniedObjectAce -> false
            | _ -> true
        sid, accessMask, objectType, isAllow


    let private readAceSize (bytes: byte array) offset =
        int (BitConverter.ToUInt16(bytes, offset + 2))


    let private getNextAceOffset curOffset aceSize =
        curOffset + (aceSize &&& ~~~3)


    ///
    /// Allow/deny phrase that replaces the old "--" separator.
    ///
    let private dispositionPhrase isAllow =
        match isAllow with
        | true -> "allowed to"
        | false -> "is denied"


    ///
    /// Format one ACE as:
    ///   Principal (allowed to|is denied) Flags
    ///   Principal (allowed to|is denied) Flags [ObjectTypeName]
    ///
    let private formatAceEntry sid accessMask objectType isAllow =
        let principal = matchKnownSids sid
        let flags = getAccessFlags accessMask
        let core = $"{principal} ({dispositionPhrase isAllow}) {flags}"
        match objectType with
        | None -> core
        | Some guid -> $"{core} [{resolveSchemaOrRightsGuid guid}]"


    ///
    /// Process one ACE: parse, format, and advance to the next.
    ///
    let private processAce (bytes: byte array) acc i offset aceCount =
        let aceSize = readAceSize bytes offset
        let sid, accessMask, objectType, isAllow = parseAceEntry bytes offset aceSize
        let formatted = formatAceEntry sid accessMask objectType isAllow
        formatted :: acc, i + 1, getNextAceOffset offset aceSize


    ///
    /// Walk all ACEs in the ACL, accumulating formatted permission strings.
    ///
    let private parseAceList (bytes: byte array) aceCount aclStart =
        let rec loop acc i offset =
            match i >= aceCount with
            | true -> acc
            | false ->
                let acc, i, offset = processAce bytes acc i offset aceCount
                loop acc i offset
        loop [] 0 aclStart


    ///
    /// Decode an NT Security Descriptor byte array into a list of human-readable
    /// permission strings:
    ///   "Principal (allowed to) Flags"
    ///   "Principal (is denied) Flags [ObjectType]"
    /// when the ACE is object-scoped.
    ///
    /// Cross-platform security descriptor + ACL parser.
    /// SD header: Revision(1) + Byte2(1) + Control(2) + Owner(4) + Group(4) + SACL(4) + DACL(4) = 20 bytes
    /// ACL header: AclRevision(1) + Unused(1) + Size(2) + AceCount(2) + Unused(2) = 8 bytes
    ///
    let internal decodeNtSecurityDescriptor (bytes: byte array) =
        let daclOffset = BitConverter.ToInt32(bytes, 16)
        match daclOffset = 0 with
        | true -> []
        | false ->
            let aceCount = int (BitConverter.ToUInt16(bytes, daclOffset + 4))
            let aclStart = daclOffset + 8
            parseAceList bytes aceCount aclStart
