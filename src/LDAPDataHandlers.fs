namespace Fiewport

module LDAPDataHandlers =
    open System
    open System.Text
    open System.Net
    open System.Security.AccessControl
    open System.Security.Principal
    open System.Security.Cryptography.X509Certificates
    open Types
    open LDAPConstants


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
            
        let descriptor = CommonSecurityDescriptor(false, false, bytes, 0) // need to check into these flags to make sure I'm not reading these incorrectly
        [for dacl in descriptor.DiscretionaryAcl do yield dacl]
        |> List.map (fun dacl ->
            match dacl with
            | :? CommonAce as common ->
                let flags = getAccessFlags common.AccessMask
                $"{matchKnownSids common.SecurityIdentifier.Value}--{flags}"
            | _ -> "")
        |> List.filter (fun p -> p <> "")


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
                [SecurityIdentifier(b, 0) |> _.Value |> fun s -> s.Trim() |> ADString]
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
                [SecurityIdentifier(b, 0) |> _.Value |> fun s -> s.Trim() |> ADString]
                |> fun strings -> map.Add("securityidentifier", strings)
            | _ -> map
        | false -> map

    
    let internal handleUserCertificate (map: Map<string, ADDataTypes list>) =
        match map.ContainsKey "usercertificate" with
        | true ->
            let certBytes = map["usercertificate"]
            let map = map.Remove "usercertificate"
            match certBytes with
            | [ADBytes b] ->
                let cert = new X509Certificate(b) // this generates a warning now for dotnet 9, wants me to use X509CertificateLoader
                let stringify =
                    [$"Issuer: {cert.Issuer}".Trim () |> ADString] @
                    [$"Subject: {cert.Subject}".Trim () |> ADString] @
                    [$"PubKey: 0x{cert.GetPublicKey () |> BitConverter.ToString |> String.filter(fun p -> p <> '-')}".Trim () |> ADString]
                cert.Dispose ()
                stringify |> fun strings -> map.Add("usercertificate", strings)
            | _ -> map
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


    let handleUserAccountControl (map: Map<string, string list>) =
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
             let value = map["samaccounttype"] |> List.head
             let map = map.Remove "samaccounttype"
             map.Add("samaccounttype", sAMAccountTypesList |> List.filter (fun p -> (int value &&& int p) = int p) |> List.map _.ToString())
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