namespace Fiewport

open System

module LDAPUtils =     

    open System.Security.AccessControl
    open System.DirectoryServices.Protocols
    open System.Net

    open Types
    open LDAPConstants


    let internal readyLDAPSearch config =
        let ldapIdentifier = LdapDirectoryIdentifier(config.ldapHost) // does this work with ldap://?
        let credential = NetworkCredential(config.username, config.password)
        let connection = new LdapConnection(ldapIdentifier, credential)    
        let searchRequest =
            SearchRequest(config.ldapDN, config.filter, config.scope, config.properties)
            |> fun sr ->
                sr.Controls.Add(SecurityDescriptorFlagControl(SecurityMasks.Dacl ||| SecurityMasks.Group ||| SecurityMasks.Owner)) |> ignore
                sr
        (connection, searchRequest)

    let internal matchKnownSids sid =        
        if wellKnownSids.ContainsKey sid then wellKnownSids[sid]
        else if networkSids.ContainsKey (sid.Split '-' |> Array.last) then networkSids[sid.Split '-' |> Array.last]
        else sid    
    
    let internal getAccessFlags accessMask =
        activeDirectoryRightsList
        |> List.filter (fun enum -> (accessMask &&& int enum) = int enum)
        |> List.map (fun enum -> enum.ToString())
        |> String.concat ", "
    

    let decodeNtSecurityDescriptors bytes =
        let descriptor = CommonSecurityDescriptor(false, false, bytes, 0) // need to check into these flags to make sure I'm not reading these incorrectly
        [for dacl in descriptor.DiscretionaryAcl do yield dacl]
        |> List.map (fun dacl ->
            match dacl with
            | :? CommonAce as common ->
                let flags = getAccessFlags common.AccessMask
                $"{matchKnownSids common.SecurityIdentifier.Value}--{flags}"
            | _ -> "")
        |> List.filter (fun p -> p <> "")


    let handleNtSecurityDescriptor (map: Map<string,ADDataTypes list>) =
        match map.ContainsKey "ntsecuritydescriptor" with
        | true ->
            let ntBytes = map["ntsecuritydescriptor"]
            let map = map.Remove "ntsecuritydescriptor"
            match ntBytes with
            | [ADBytes b] ->                
                decodeNtSecurityDescriptors b
                |> List.map (fun s -> s |> ADString)
                |> fun strings -> map.Add ("ntsecuritydescriptor", strings)                
            | _ -> map
        | false -> map
    
    
    let handleObjectGuid (map: Map<string, ADDataTypes list>) =
        match map.ContainsKey "objectguid" with // should always have one, but w/e
        | true ->
            let guidBytes = map["objectguid"]
            let map = map.Remove "objectguid"
            match guidBytes with
            | [ADBytes b] ->
                [$"{b |> Guid}" |> ADString] |> fun strings -> map.Add("objectguid", strings)
            | _ -> map
        | false -> map
    
    
    let createLDAPSearchResults (searchType: LDAPSearchType) config (results: Result<SearchResponse, string>) =
        match results with
        | Ok res ->
            let ldapData = // need to handle objectsid, ntsecdes, objectguid, usercert
                [for item in res.Entries do yield item] // Extract entries
                |> List.collect (fun p ->
                    [for name in p.Attributes.AttributeNames do yield name.ToString()]// extract the names of the attributes returned
                    |> List.map (fun name -> (name, [for item in p.Attributes[name] do yield (item :?> byte array) |> ADBytes]))) // for each attribute, retrieve all values and create a tuple
                |> List.fold (fun acc (name, values) -> acc |> Map.add name values) Map.empty<string,ADDataTypes list> // create a Map to easily access values
                |> handleNtSecurityDescriptor
                |> handleObjectGuid
            
        | Error e ->
            { searchType = searchType
              searchConfig = config
              ldapSearcherError = e |> Some
              ldapData = Map.empty<string,string list> }