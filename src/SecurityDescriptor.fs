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


    let private lookupWellKnownSid (sid: string) =
        wellKnownSids.TryFind sid


    let private lookupNetworkSid (sid: string) =
        sid.Split '-'
        |> Array.last
        |> networkSids.TryFind


    /// Resolve a SID string to a human-readable name.
    /// Checks well-known SIDs first, then network SIDs by RID, falls back to raw SID.
    let private matchKnownSids sid =
        match lookupWellKnownSid sid with
        | Some name -> name
        | None ->
            match lookupNetworkSid sid with
            | Some name -> name
            | None -> sid


    let private getAccessFlags accessMask =
        activeDirectoryRightsList
        |> List.filter (fun e -> accessMask &&& int e = int e)
        |> List.map (fun e -> e.ToString())
        |> String.concat ", "


    /// Seed the context from raw ACE parameters.
    let private initAceContext (bytes: byte array) curOffset aceSize =
        { bytes = bytes; curOffset = curOffset; aceSize = aceSize; sidOffset = 0; sidSize = 0 }


    /// Reject ACEs smaller than the 8-byte header.
    let private validateAceSize (ctx: AceParseContext option) =
        ctx
        |> Option.map (fun c -> if c.aceSize < 8 then None else Some c)
        |> Option.bind id


    ///
    /// Compute where the SID begins inside an ACE
    /// Standard ACEs: SID starts at offset + 8.
    /// Object ACEs: 8-byte header + 4-byte AceFlags DWORD, then optional GUIDs (16 bytes each), then SID.
    /// 
    let private computeSidOffset (ctx: AceParseContext option) =
        ctx
        |> Option.map (fun c ->
            let aceType = c.bytes.[c.curOffset]
            let isObjectAce = aceType = accessAllowedObjectAce || aceType = accessDeniedObjectAce

            if not isObjectAce then
                Some { c with sidOffset = c.curOffset + 8 }
            else
                let aceFlagsOffset = c.curOffset + 8
                if aceFlagsOffset + 4 > Array.length c.bytes then None
                else
                    let objFlags = BitConverter.ToInt32(c.bytes, aceFlagsOffset)
                    let addGuidIfPresent flag acc = if objFlags &&& flag <> 0 then acc + 16 else acc
                    let extraBytes =
                        0 |> addGuidIfPresent aceObjectTypePresent |> addGuidIfPresent aceInheritedObjectTypePresent
                    // SID follows the AceFlags DWORD + any present GUIDs
                    Some { c with sidOffset = aceFlagsOffset + 4 + extraBytes })
        |> Option.bind id


    /// Verify the SID region is large enough and within bounds.
    let private validateSidBounds (ctx: AceParseContext option) =
        ctx
        |> Option.map (fun c ->
            let sidSize = c.aceSize - (c.sidOffset - c.curOffset)
            if sidSize < 8 || c.sidOffset + sidSize > Array.length c.bytes then None
            else Some { c with sidSize = sidSize })
        |> Option.bind id


    /// Decode the SID and read the access mask from the ACE header.
    let private extractSidAndAccessMask (ctx: AceParseContext option) =
        ctx
        |> Option.map (fun c ->
            decodeSidFromBytes (Array.sub c.bytes c.sidOffset c.sidSize),
            BitConverter.ToInt32(c.bytes, c.curOffset + 4))


    /// Parse a single ACE entry through the validation pipeline.
    let private parseAceEntry (bytes: byte array) curOffset aceSize =
        Some (initAceContext bytes curOffset aceSize)
        |> validateAceSize
        |> computeSidOffset
        |> validateSidBounds
        |> extractSidAndAccessMask


    let private readAceSize (bytes: byte array) offset =
        int (BitConverter.ToUInt16(bytes, offset + 2))


    let private getNextAceOffset curOffset aceSize =
        if aceSize < 8 then curOffset + 4 else curOffset + (aceSize &&& ~~~3)


    let private formatAceEntry sid accessMask =
        $"{matchKnownSids sid}--{getAccessFlags accessMask}"


    /// Walk all ACEs and populate the permissions list.
    let private parseAclEntries ctx =
        if not ctx.valid then { ctx with permissions = [] }
        else
            let rec loop acc i curOffset =
                if i >= ctx.aceCount || curOffset + 8 > Array.length ctx.bytes then
                    acc
                else
                    let aceSize = readAceSize ctx.bytes curOffset
                    let nextOffset = getNextAceOffset curOffset aceSize
                    match parseAceEntry ctx.bytes curOffset aceSize with
                    | None -> loop acc (i + 1) nextOffset
                    | Some (sid, accessMask) ->
                        loop (formatAceEntry sid accessMask :: acc) (i + 1) nextOffset
            { ctx with permissions = loop [] 0 ctx.aclStart }


    /// Seed the context from raw bytes.
    let private init bytes =
        { bytes = bytes; valid = true; daclOffset = 0; aceCount = 0; aclStart = 0; permissions = [] }


    /// Verify the SD is long enough to hold its 20-byte header.
    let private validateSdHeader ctx =
        { ctx with valid = Array.length ctx.bytes >= 20 }


    /// Read the DACL pointer from the SD header (DWORD at offset 16).
    let private extractDaclOffset ctx =
        let daclOffset = if ctx.valid then BitConverter.ToInt32(ctx.bytes, 16) else 0
        { ctx with daclOffset = daclOffset }


    /// Ensure the DACL pointer is valid (non-null, room for ACL header).
    let private validateDaclOffset ctx =
        let offsetValid = ctx.daclOffset <> 0 && ctx.daclOffset + 8 <= Array.length ctx.bytes
        { ctx with valid = ctx.valid && offsetValid }


    /// Pull ACE count and compute where ACE data begins.
    let private extractAclInfo ctx =
        let aceCount = if ctx.valid then int (BitConverter.ToUInt16(ctx.bytes, ctx.daclOffset + 4)) else 0
        let aclStart = if ctx.valid then ctx.daclOffset + 8 else 0
        { ctx with aceCount = aceCount; aclStart = aclStart }

    /// Extract the final permissions list, returning [] if pipeline failed.
    let private finalize ctx =
        if ctx.valid then ctx.permissions else []

    ///
    /// Decode an NT Security Descriptor byte array into a list of human-readable
    /// permission strings in the form "Principal--Flags".
    ///
    /// Cross-platform security descriptor + ACL parser.
    /// SD header: Revision(1) + Byte2(1) + Control(2) + Owner(4) + Group(4) + SACL(4) + DACL(4) = 20 bytes
    /// ACL header: AclRevision(1) + Unused(1) + Size(2) + AceCount(2) + Unused(2) = 8 bytes
    ///
    /// Pipeline: init → validateSdHeader → extractDaclOffset → validateDaclOffset →
    ///           extractAclInfo → parseAclEntries → finalize
    /// 
    let internal decodeNtSecurityDescriptor bytes =
        bytes
        |> init
        |> validateSdHeader
        |> extractDaclOffset
        |> validateDaclOffset
        |> extractAclInfo
        |> parseAclEntries
        |> finalize
