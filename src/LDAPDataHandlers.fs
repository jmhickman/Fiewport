namespace Fiewport

module LDAPDataHandlers =
    open System
    open System.Text
    open System.Net
    open System.Security.Cryptography.X509Certificates
    open Types
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
                int bytes[2] <<< 32 ||| 
                (int bytes[3] <<< 24) ||| 
                (int bytes[4] <<< 16) ||| 
                (int bytes[5] <<< 8) ||| 
                int bytes[6] ||| 
                (int bytes[7] &&& 0xFF)
                |> int64
                |> int32

            let subAuthorities =
                [for i in 0 .. subAuthCount - 1 do
                    let offset = 8 + (i * 4)
                    if offset + 4 <= Array.length bytes then
                        yield sprintf "%u" (BitConverter.ToUInt32(bytes, offset))]

            $"""S-{revision}-{authority}-{String.concat "-" subAuthorities}"""

    let internal decodeNtSecurityDescriptors bytes =
        let matchKnownSids sid =
            if wellKnownSids.ContainsKey sid then wellKnownSids[sid]
            else if networkSids.ContainsKey (sid.Split '-' |> Array.last) then networkSids[sid.Split '-' |> Array.last]
            else sid
            
        let getAccessFlags accessMask =
            activeDirectoryRightsList
            |> List.filter (fun enum -> (accessMask &&& int enum) = int enum)
            |> List.map (fun enum -> enum.ToString())
            |> String.concat ", "
        
        // Cross-platform security descriptor + ACL parser
        // SD header: Revision(1) + Byte2(1) + Control(2) + Owner(4) + Group(4) + SACL(4) + DACL(4) = 20 bytes
        let parseSd (bytes: byte[]) =
            if Array.length bytes < 20 then []
            else
                // Get DACL offset from security descriptor header (offset 16-19)
                let daclOffset = BitConverter.ToInt32(bytes, 16)
                if daclOffset = 0 || daclOffset + 8 > Array.length bytes then []
                else
                    // ACL header: AclRevision(1) + Unused(1) + Size(2) + AceCount(2) + Unused(2) = 8 bytes
                    let aceCount = int (BitConverter.ToUInt16(bytes, daclOffset + 4))
                    let aclStart = daclOffset + 8
                    let rec loop acc i curOffset =
                        if i >= aceCount || curOffset + 8 > Array.length bytes then acc
                        else
                            let aceType = bytes[curOffset]
                            let aceSize = int (BitConverter.ToUInt16(bytes, curOffset + 2))
                            if aceSize < 8 then
                                loop acc (i + 1) (curOffset + 4)
                            else
                                let sidOffset = curOffset + 8
                                let sidSize = aceSize - 8
                                let nextOffset = curOffset + (aceSize &&& ~~~3) // round up to 4-byte boundary
                                if sidOffset + sidSize > Array.length bytes then
                                    loop acc (i + 1) nextOffset
                                else
                                    let sidBytes = Array.sub bytes sidOffset sidSize
                                    let sid = decodeSidFromBytes sidBytes
                                    let accessMask = BitConverter.ToInt32(bytes, curOffset + 4)
                                    let flags = getAccessFlags accessMask
                                    let entry = $"{matchKnownSids sid}--{flags}"
                                    loop (entry :: acc) (i + 1) nextOffset
                    loop [] 0 aclStart
        
        parseSd bytes


    let internal handleNtSecurityDescriptor (map: Map<string,ADDataTypes list>) =
        match map.ContainsKey "ntsecuritydescriptor" with
        | true ->
            let ntBytes = map["ntsecuritydescriptor"]
            let map = map.Remove "ntsecuritydescriptor"
            match ntBytes with
            | [ADBytes b] ->                
                decodeNtSecurityDescriptors b
                |> List.map (fun s -> s.Trim() |> ADString)
                |> fun strings -> map.Add ("ntsecuritydescriptor", strings)                
            | _ -> map
        | false -> map


    let internal handleDNSRecord (map: Map<string,ADDataTypes list>) =
        let extract (dnsRecord: byte[]) =
            let data = dnsRecord[24..]

            match BitConverter.ToUInt16(dnsRecord, 2) with // extract the type
            | 0x01us -> // A record
                IPAddress(data[..3]).ToString() |> ADString
            | 0x1Cus -> // AAAA record
                IPAddress(data[..15]).ToString() |> ADString
            | _ -> "" |> ADString
        
        match map.ContainsKey "dnsrecord" with
        | true ->
            let ntBytes = map["dnsrecord"]
            let map = map.Remove "dnsrecord"
            match ntBytes with
            | [ADBytes b] -> map.Add("dnsrecord", [extract b])                              
            | _ -> map
        | false -> map


    let internal handleObjectGuid (map: Map<string, ADDataTypes list>) =
        match map.ContainsKey "objectguid" with // should always have one, but w/e
        | true ->
            let guidBytes = map["objectguid"]
            let map = map.Remove "objectguid"
            match guidBytes with
            | [ADBytes b] ->
                [$"{b |> Guid}".Trim () |> ADString]
                |> fun strings -> map.Add("objectguid", strings)
            | _ -> map
        | false -> map


    let internal handlemsdfsrReplicationGroupGuid (map: Map<string, ADDataTypes list>) =
        match map.ContainsKey "msdfsr-replicationgroupguid" with
        | true ->
            let guidBytes = map["msdfsr-replicationgroupguid"]
            let map = map.Remove "msdfsr-replicationgroupguid"
            match guidBytes with
            | [ADBytes b] ->
                [$"{b |> Guid}".Trim () |> ADString]
                |> fun strings -> map.Add("msdfsr-replicationgroupguid", strings)
            | _ -> map
        | false -> map

        
    let internal handleLogonHours (map: Map<string, ADDataTypes list>) =
        let decider bytes =
            if bytes >= 32uy && bytes <= 126uy then $"{bytes}"
            else $"%02X{bytes}" 
        
        match map.ContainsKey "logonhours" with // should always have one, but w/e
        | true ->
            let logonBytes = map["logonhours"]
            let map = map.Remove "logonhours"
            match logonBytes with
            | [ADBytes bytes] ->
                bytes
                |> Array.map decider
                |> List.ofArray
                |> String.concat " " |> ADString
                |> fun strings -> map.Add("logonhours", [strings])
            | _ -> map
        | false -> map

        
    let internal handleObjectSid (map: Map<string, ADDataTypes list>) =
        match map.ContainsKey "objectsid" with
        | true ->
            let sidBytes = map["objectsid"]
            let map = map.Remove "objectsid"
            match sidBytes with
            | [ADBytes b] ->
                [decodeSidFromBytes b |> ADString]
                |> fun strings -> map.Add("objectsid", strings)
            | _ -> map
        | false -> map


    let internal handleSecurityIdentifier (map: Map<string, ADDataTypes list>) =
        match map.ContainsKey "securityidentifier" with
        | true ->
            let sidBytes = map["securityidentifier"]
            let map = map.Remove "securityidentifier"
            match sidBytes with
            | [ADBytes b] ->
                [decodeSidFromBytes b |> ADString]
                |> fun strings -> map.Add("securityidentifier", strings)
            | _ -> map
        | false -> map

    
    let internal handleUserCertificate (map: Map<string, ADDataTypes list>) =
        let dash = '-'
        let stripDashes (s: string) = String.filter (fun c -> c <> dash) s
        
        match map.ContainsKey "usercertificate" with
        | true ->
            let certBytes = map["usercertificate"]
            let map = map.Remove "usercertificate"
            let decodeCert (b: byte[]) =
                try
                    let cert = X509CertificateLoader.LoadCertificate b
                    let issuer = sprintf "Issuer: %s" cert.Issuer
                    let subject = sprintf "Subject: %s" cert.Subject
                    let pubKey = sprintf "PubKey: 0x%s" (cert.GetPublicKey() |> BitConverter.ToString |> stripDashes)
                    cert.Dispose()
                    [ADString issuer; ADString subject; ADString pubKey]
                with _ -> []
            let strings = certBytes |> List.collect (function ADBytes b -> decodeCert b | _ -> [])
            if List.isEmpty strings then map
            else map.Add("usercertificate", strings)
        | false -> map

        
    let internal handleDSASignature (map: Map<string, ADDataTypes list>) =
        match map.ContainsKey "dsasignature" with
        | true ->
            let value = map["dsasignature"] |> List.head
            let h = match value with
                    | ADBytes b -> b |> BitConverter.ToString |> _.Replace("-", "") |> ADString
                    | _ -> ""  |> ADString
            let map = map.Remove "dsasignature"
            map.Add("dsasignature", [h])
        | false -> map


    let internal handleBigEndianIntegers (map: Map<string, ADDataTypes list>) =
        let decodeBigEndianInt64 (b: byte[]) =
            if Array.length b = 8 then
                Int64.Parse(BitConverter.ToString(b).Replace("-", ""), System.Globalization.NumberStyles.HexNumber) |> string |> ADString
            elif Array.length b = 4 then
                BitConverter.ToUInt32(b, 0) |> string |> ADString
            else
                BitConverter.ToString(b).Replace("-", "") |> ADString
        
        let keysToHandle = [ "msds-generationid"; "hidesqlinkedvalue"; "mssql-replicationid" ]
        let rec loop (map: Map<string, ADDataTypes list>) (keys: string list) =
            match keys with
            | [] -> map
            | key :: rest ->
                match map.ContainsKey key with
                | false -> loop map rest
                | true ->
                    let values = map[key]
                    let map = map.Remove key
                    let decoded = values |> List.collect (function ADBytes b -> [decodeBigEndianInt64 b] | ADString s -> [ADString s])
                    loop (map.Add(key, decoded)) rest
        loop map keysToHandle


    let internal handleGenericStrings (map: Map<string, ADDataTypes list>) =
        let decomposeList (adList: ADDataTypes list) =
            adList
            |> List.map(fun adItem ->
                match adItem with
                | ADString s -> $"{s}"
                | ADBytes b -> $"{Encoding.UTF8.GetString(b)}".Trim ())
        let keys = [for key in map.Keys do yield key]
        let pairs = [for key in keys do yield (key, (decomposeList map[key]))]
        pairs |> List.fold(fun acc (key, value) -> acc |> Map.add key value ) Map.empty<string,string list>


    let internal handleThingsWithTicks (map: Map<string, string list>) =
        let returnTicksAfterEpoch ticks =
            let ticks' = Int64.Parse ticks
            match ticks' with
            | Int64.MaxValue -> "no expiry"
            | 0L -> "never logged in/out"
            | _ ->
                beginningOfEpoch
                |> fun epoch -> epoch.AddTicks ticks'
                |> fun date -> date.ToShortDateString ()
        
        let decider (map: Map<string, string list>) key =
            match map.ContainsKey key with
            | true ->
                let value = map[key] |> List.head
                let map = map.Remove key
                map.Add(key, [returnTicksAfterEpoch value])
            | false -> map
        
        [ "accountexpires"
          "badpasswordtime"
          "creationtime"
          "lastlogoff"
          "lastlogon"
          "pwdlastset"
          "lastlogontimestamp" ]
        |> List.fold decider map


    let handleThingsWithTimespans (map: Map<string, string list>) =
        let returnTimespan ticks =
            let ticks' = Int64.Parse ticks
            match ticks' with
            | Int64.MinValue -> "no expiry"
            | _ -> TimeSpan.FromTicks (abs ticks') |> fun time -> time.TotalHours.ToString ()
        
        let decider (map: Map<string, string list>) key =
            match map.ContainsKey key with
            | true ->
                let value = map[key] |> List.head
                let map = map.Remove key
                map.Add(key, [returnTimespan value])
            | false -> map
        
        [ "forcelogoff" 
          "lockoutduration" 
          "lockoutobservationwindow"     
          "maxpwdage" 
          "minpwdage" ]
        |> List.fold decider map


    let handleThingsWithZulus (map: Map<string, string list>) =
        let returnDateFromZulu zuluString =
            let format = "yyyyMMddHHmmss.fZ"
            DateTime.ParseExact(zuluString, format, System.Globalization.CultureInfo.InvariantCulture)
            |> fun date -> $"{date.ToShortDateString ()} {date.ToShortTimeString ()}"
        
        let decider (map: Map<string, string list>) key =
            match map.ContainsKey key with
            | true ->
                let value = map[key]
                let map = map.Remove key
                map.Add(key, value |> List.map returnDateFromZulu )
            | false -> map
        
        [ "whenchanged"
          "whencreated"
          "dscorepropagationdata" ]
        |> List.fold decider map
 

    let handleGroupType (map: Map<string, string list>) =
        match map.ContainsKey "grouptype" with
        | true ->
            let value = map["grouptype"] |> List.head
            let map = map.Remove "grouptype"
            map.Add("grouptype", groupTypeList |> List.filter (fun p -> (int value &&& int p) = int p) |> List.map _.ToString())
        | false -> map


    let handleSystemFlags (map: Map<string, string list>) =
        match map.ContainsKey "systemflags" with
        | true ->
            let value = map["systemflags"] |> List.head
            let map = map.Remove "systemflags"
            map.Add("systemflags", systemFlagsList |> List.filter (fun p -> (int value &&& int p) = int p) |> List.map _.ToString())
        | false -> map


    let internal handleUserAccountControl (map: Map<string, string list>) =
        let readUserAccountControl bits =
            [for i in 0..31 do if ((int bits >>> i) &&& 1) = 1 then yield uacPropertyFlags[i]]
            
        match map.ContainsKey "useraccountcontrol" with
        | true ->
            let value = map["useraccountcontrol"] |> List.head
            let map = map.Remove "useraccountcontrol"
            map.Add("useraccountcontrol", readUserAccountControl value)
        | false -> map


    let handleSamAccountType (map: Map<string, string list>) =
         match map.ContainsKey "samaccounttype" with
         | true ->
             let value = map["samaccounttype"] |> List.head |> int
             let map = map.Remove "samaccounttype"
             // SAMAccountType values are not pure bitmasks — find the most specific match
             let matches = sAMAccountTypesList |> List.filter (fun p -> (value &&& int p) = int p)
             // Prefer the most specific (highest value that matches)
             let result = if List.length matches > 1 then [List.max matches] else matches
             map.Add("samaccounttype", result |> List.map _.ToString())
         | false -> map


    let handlemsdsSupportedEncryptionType (map: Map<string, string list>) =
         let readmsDSSupportedEncryptionTypes (bits: string) = msdsSupportedEncryptionTypes[int bits]
         
         match map.ContainsKey "msds-supportedencryptiontypes" with
         | true ->
             let value = map["msds-supportedencryptiontypes"] |> List.head
             let map = map.Remove "msds-supportedencryptiontypes"
             map.Add("msds-supportedencryptiontypes", [readmsDSSupportedEncryptionTypes value])
         | false -> map


    let handleWellKnownThings (map: Map<string, string list>) =
        let splitAndSplice (value: string list) =
            [for item in value do
                let splits = item.Split ':'
                let guid = Guid.Parse(splits[2])
                let dn = splits[3]
                yield $"{guid} -> {dn}"]
        
        let decider (map: Map<string, string list>) key =
            match map.ContainsKey key with
            | true ->
                let value = map[key]
                let map = map.Remove key                
                map.Add(key, splitAndSplice value)
            | false -> map
        
        [ "wellknownobjects"
          "otherwellknownobjects" ]
        |> List.fold decider map


    let handleInstanceType (map: Map<string, string list>) =
         match map.ContainsKey "instancetype" with
         | true ->
             let value = map["instancetype"] |> List.head
             let map = map.Remove "instancetype"
             map.Add("instancetype", instanceTypesList |> List.filter (fun p -> (int value &&& int p) = int p) |> List.map _.ToString())
         | false -> map
         
         
    let handleRepSto (map: Map<string, string list>) =
         match map.ContainsKey "repsto" with
         | true -> map.Remove "repsto"
         | false -> map


    let handleTrustAttibutes (map: Map<string, string list>) =
         match map.ContainsKey "trustattributes" with
         | true ->
             let value = map["trustattributes"] |> List.head
             let map = map.Remove "trustattributes"
             map.Add("trustattributes", trustAttributesList |> List.filter (fun p -> (int value &&& int p) = int p) |> List.map _.ToString())
         | false -> map
         
         
    let handleTrustDirection (map: Map<string, string list>) =
         match map.ContainsKey "trustdirection" with
         | true ->
             let value = map["trustdirection"] |> List.head
             let map = map.Remove "trustdirection"
             map.Add("trustdirection", trustDirectionList |> List.filter (fun p -> (int value = int p)) |> List.map _.ToString())
         | false -> map


    let handleTrustType (map: Map<string, string list>) =
         match map.ContainsKey "trusttype" with
         | true ->
             let value = map["trusttype"] |> List.head
             let map = map.Remove "trusttype"
             map.Add("trusttype", trustTypeList |> List.filter (fun p -> (int value &&& int p) = int p) |> List.map _.ToString())
         | false -> map

    // domain trust types:  trustposixoffset