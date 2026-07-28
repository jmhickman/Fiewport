module ByteHandlerTests

open Expecto
open Fiewport.Types
open Fiewport.LDAPDataHandlers

let private hexToBytes (hex: string) : byte [] =
    hex.Split('-') |> Array.map (fun s -> System.Byte.Parse(s, System.Globalization.NumberStyles.HexNumber, null)) |> Array.copy

// Real domain SID from raw dump: S-1-5-21-4234567890-1234567890-1234567890
let private domainSidBytes = hexToBytes "01-05-00-00-00-00-00-05-15-00-00-00-40-B2-8A-45-26-CC-AE-5A-B2-3F-35-E8"

// Real user SID (RID 0x01F4 = 500) from raw dump
let private userSidBytes = hexToBytes "01-05-00-00-00-00-00-05-15-00-00-00-40-B2-8A-45-26-CC-AE-5A-B2-3F-35-E8-F4-01-00-00"

// Real domain SID (no RID) from raw dump
let private domainSidNoRid = hexToBytes "01-04-00-00-00-00-00-05-15-00-00-00-40-B2-8A-45-26-CC-AE-5A-B2-3F-35-E8"

// Real ObjectGUID from raw dump
let private realObjectGuid = hexToBytes "A3-17-AC-76-EB-0B-63-45-83-69-0F-DB-44-E9-36-5D"

// Real DNS record from raw dump (AAAA record, 40 bytes)
let private realDnsRecord = hexToBytes "10-00-1C-00-05-08-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-20-01-05-03-BA-3E-00-00-00-00-00-00-00-02-00-30"

// Real DSA signature from raw dump (40 bytes)
let private realDsaSignature = hexToBytes "01-00-00-00-28-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-67-0A-36-BA-55-10-3C-4A-BB-E0-D5-01-2E-05-39-9C"

// Real certificate header from raw dump (first 64 bytes of X.509)
let private certBytes = hexToBytes "30-82-06-62-30-82-05-4A-A0-03-02-01-02-02-13-51-00-00-00-03-D5-9E-03-77-4A-9B-AB-23-00-00-00-00-00-03-30-0D-06-09-2A-86-48-86-F7-0D-01-01-0B-05-00-30-50-31-15-17-13-61-64-2D-6C-61-62-2E-6C-6F-63-61-6C-31-18-30-16-06-09-60-86-48-01-86-F7-12-01-01"

// msds-optionalfeatureguid: Recycle Bin Feature (766ddcd8-acd0-445e-f3b9-a7f9b6744f2a)
// .NET Guid(byte[]) reads first 3 fields little-endian, last field big-endian
let private recycleBinGuid = hexToBytes "D8-DC-6D-76-D0-AC-5E-44-F3-B9-A7-F9-B6-74-4F-2A"
// msds-optionalfeatureguid: Privileged Access Management (ec43e873-cce8-4640-b4ab-07ffe4ab5bcd)
let private pamGuid = hexToBytes "73-E8-43-EC-E8-CC-40-46-B4-AB-07-FF-E4-AB-5B-CD"

// ========== Byte Handler Tests ==========

let ``handles SID objectsid`` () =
    let input = Map.ofList [ "objectsid", [ADBytes userSidBytes] ]
    let result = handleObjectSid input
    Expect.isTrue (Map.containsKey "objectsid" result) "objectsid key preserved"
    
    match Map.tryFind "objectsid" result with
    | Some [ADString s] ->
        Expect.isTrue (s.StartsWith("S-")) "decoded to SID string"
        Expect.isTrue (s.Contains("-500")) "contains RID"
    | _ -> Expect.isTrue false "expected string result"

let ``handles SID objectsid missing`` () =
    let input = Map.ofList [ "cn", [ADString "test"] ]
    let result = handleObjectSid input
    Expect.isFalse (Map.containsKey "objectsid" result) "no objectsid added"

let ``handles ObjectGUID`` () =
    let input = Map.ofList [ "objectguid", [ADBytes realObjectGuid] ]
    let result = handleObjectGuid input
    
    match Map.tryFind "objectguid" result with
    | Some [ADString s] ->
        Expect.equal s.Length 36 "GUID format (36 chars)"
        Expect.isTrue (s.Contains("-")) "contains dashes"
    | _ -> Expect.isTrue false "expected string result"

let ``handles ObjectGUID missing`` () =
    let input = Map.ofList [ "cn", [ADString "test"] ]
    let result = handleObjectGuid input
    Expect.isFalse (Map.containsKey "objectguid" result) "no objectguid added"

let ``handles msds-optionalfeatureguid single`` () =
    let input = Map.ofList [ "msds-optionalfeatureguid", [ADBytes recycleBinGuid] ]
    let result = handlemsdsOptionalFeatureGuid input
    
    match Map.tryFind "msds-optionalfeatureguid" result with
    | Some [ADString s] ->
        Expect.equal s "766ddcd8-acd0-445e-f3b9-a7f9b6744f2a" "Recycle Bin GUID decoded"
    | _ -> Expect.isTrue false "expected single GUID string"

let ``handles msds-optionalfeatureguid multiple`` () =
    let input = Map.ofList [ "msds-optionalfeatureguid", [ADBytes recycleBinGuid; ADBytes pamGuid] ]
    let result = handlemsdsOptionalFeatureGuid input
    
    match Map.tryFind "msds-optionalfeatureguid" result with
    | Some vals ->
        Expect.equal (List.length vals) 2 "both GUIDs decoded"
        
        match vals with
        | [ADString a; ADString b] ->
            Expect.equal a "766ddcd8-acd0-445e-f3b9-a7f9b6744f2a" "first GUID correct"
            Expect.equal b "ec43e873-cce8-4640-b4ab-07ffe4ab5bcd" "second GUID correct"
        | _ -> Expect.isTrue false "expected two ADStrings"
    | _ -> Expect.isTrue false "expected string results"

let ``handles msds-optionalfeatureguid missing`` () =
    let input = Map.ofList [ "cn", [ADString "test"] ]
    let result = handlemsdsOptionalFeatureGuid input
    Expect.isFalse (Map.containsKey "msds-optionalfeatureguid" result) "no key added"

let ``handles DNS record`` () =
    let input = Map.ofList [ "dnsrecord", [ADBytes realDnsRecord] ]
    let result = handleDNSRecord input
    Expect.isTrue (Map.containsKey "dnsrecord" result) "dnsrecord preserved"
    
    match Map.tryFind "dnsrecord" result with
    | Some [ADString s] ->
        Expect.isTrue (s.Length > 0) "decoded to non-empty string"
    | _ -> Expect.isTrue false "expected string result"

let ``handles DNS record missing`` () =
    let input = Map.ofList [ "cn", [ADString "test"] ]
    let result = handleDNSRecord input
    Expect.isFalse (Map.containsKey "dnsrecord" result) "no dnsrecord added"

let ``handles DSA signature`` () =
    let input = Map.ofList [ "dsasignature", [ADBytes realDsaSignature] ]
    let result = handleDSASignature input
    
    match Map.tryFind "dsasignature" result with
    | Some [ADString s] ->
        Expect.isTrue (s.Length > 0) "decoded to non-empty string"
    | _ -> Expect.isTrue false "expected string result"

let ``handles DSA signature missing`` () =
    let input = Map.ofList [ "cn", [ADString "test"] ]
    let result = handleDSASignature input
    Expect.isFalse (Map.containsKey "dsasignature" result) "no dsasignature added"

let ``handles UserCertificate`` () =
    // Real certificate from raw dump (1638 bytes)
    let cert = hexToBytes "30-82-06-62-30-82-05-4A-A0-03-02-01-02-02-13-51-00-00-00-03-D5-9E-03-77-4A-9B-AB-23-00-00-00-00-00-03-30-0D-06-09-2A-86-48-86-F7-0D-01-01-0B-05-00-30-50-31-15-30-13-06-0A-09-92-26-89-93-F2-2C-64-01-19-16-05-6C-6F-63-61-6C-31-16-30-14-06-0A-09-92-26-89-93-F2-2C-64-01-19-16-06-61-64-2D-6C-61-62-31-1F-30-1D-06-03-55-04-03-13-16-61-64-2D-6C-61-62-2D-41-44-2D-53-45-52-56-45-52-2D-30-31-2D-43-41-30-1E-17-0D-32-36-30-37-32-32-30-34-30-32-32-32-5A-17-0D-32-37-30-37-32-32-30-34-30-32-32-32-5A-30-24-31-22-30-20-06-03-55-04-03-13-19-41-44-2D-53-65-72-76-65-72-2D-30-31-2E-61-64-2D-6C-61-62-2E-6C-6F-63-61-6C-30-82-01-22-30-0D-06-09-2A-86-48-86-F7-0D-01-01-01-05-00-03-82-01-0F-00-30-82-01-0A-02-82-01-01-00-EA-3B-BE-B8-18-AC-7C-71-8F-B5-BA-0A-DE-85-3D-A0-B0-31-2A-16-B3-76-BE-01-CC-79-40-24-BF-97-37-5D-69-AF-92-3E-7C-53-FB-DA-E8-79-E4-A5-9D-5E-B1-AC-35-3E-8B-3F-1F-33-D4-D4-21-53-FD-B1-26-27-1F-64-21-3B-44-A4-FE-3B-C2-23-07-F0-60-C9-9C-42-6E-93-C4-E9-95-67-95-76-67-0F-61-F6-F1-25-14-AF-D6-B9-BF-D6-FF-6B-EA-A0-66-BE-63-57-1A-7D-B0-C3-9D-7B-54-BF-DB-23-5A-93-08-10-75-97-A0-AC-2E-E1-18-79-13-3B-B0-03-9D-70-BB-81-B7-4B-99-FD-60-E5-22-0A-1D-2C-16-83-1A-E5-21-15-F2-C8-49-7C-8B-70-60-D7-BF-C0-8D-16-C4-44-1A-F7-43-0E-05-A6-09-2A-20-17-B8-00-8A-02-FF-C5-87-3D-9E-E5-0C-09-40-AC-F3-FC-62-F6-8E-C6-FB-78-5C-A7-B2-20-D4-15-AE-41-86-2A-77-6C-F2-01-19-9F-FF-EB-05-24-79-6D-D5-D0-B3-49-FC-30-35-8A-2E-CF-5F-25-BD-BF-BB-A6-10-A6-F3-9B-FC-93-A4-BB-97-6A-48-4F-7D-1E-96-6B-A4-9E-45-35-02-03-01-00-01-A3-82-03-5F-30-82-03-5B-30-2F-06-09-2B-06-01-04-01-82-37-14-02-04-22-1E-20-00-44-00-6F-00-6D-00-61-00-69-00-6E-00-43-00-6F-00-6E-00-74-00-72-00-6F-00-6C-00-6C-00-65-00-72-30-1D-06-03-55-1D-25-04-16-30-14-06-08-2B-06-01-05-05-07-03-02-06-08-2B-06-01-05-05-07-03-01-30-0E-06-03-55-1D-0F-01-01-FF-04-04-03-02-05-A0-30-78-06-09-2A-86-48-86-F7-0D-01-09-0F-04-6B-30-69-30-0E-06-08-2A-86-48-86-F7-0D-03-02-02-02-00-80-30-0E-06-08-2A-86-48-86-F7-0D-03-04-02-02-00-80-30-0B-06-09-60-86-48-01-65-03-04-01-2A-30-0B-06-09-60-86-48-01-65-03-04-01-2D-30-0B-06-09-60-86-48-01-65-03-04-01-02-30-0B-06-09-60-86-48-01-65-03-04-01-05-30-07-06-05-2B-0E-03-02-07-30-0A-06-08-2A-86-48-86-F7-0D-03-07-30-1D-06-03-55-1D-0E-04-16-04-14-D4-47-6A-90-FD-84-40-A7-70-EA-2B-98-F7-10-AC-A6-41-65-07-70-30-1F-06-03-55-1D-23-04-18-30-16-80-14-9B-B1-F6-71-7D-96-E7-35-89-70-8A-A9-A0-D8-CC-A9-CA-BD-5C-9B-30-81-DA-06-03-55-1D-1F-04-81-D2-30-81-CF-30-81-CC-A0-81-C9-A0-81-C6-86-81-C3-6C-64-61-70-3A-2F-2F-2F-43-4E-3D-61-64-2D-6C-61-62-2D-41-44-2D-53-45-52-56-45-52-2D-30-31-2D-43-41-2C-43-4E-3D-41-44-2D-53-65-72-76-65-72-2D-30-31-2C-43-4E-3D-43-44-50-2C-43-4E-3D-50-75-62-6C-69-63-25-32-30-4B-65-79-25-32-30-53-65-72-76-69-63-65-73-2C-43-4E-3D-53-65-72-76-69-63-65-73-2C-43-4E-3D-43-6F-6E-66-69-67-75-72-61-74-69-6F-6E-2C-44-43-3D-61-64-2D-6C-61-62-2C-44-43-3D-6C-6F-63-61-6C-3F-63-65-72-74-69-66-69-63-61-74-65-52-65-76-6F-63-61-74-69-6F-6E-4C-69-73-74-3F-62-61-73-65-3F-6F-62-6A-65-63-74-43-6C-61-73-73-3D-63-52-4C-44-69-73-74-72-69-62-75-74-69-6F-6E-50-6F-69-6E-74-30-81-C9-06-08-2B-06-01-05-05-07-01-01-04-81-BC-30-81-B9-30-81-B6-06-08-2B-06-01-05-05-07-30-02-86-81-A9-6C-64-61-70-3A-2F-2F-2F-43-4E-3D-61-64-2D-6C-61-62-2D-41-44-2D-53-45-52-56-45-52-2D-30-31-2D-43-41-2C-43-4E-3D-41-49-41-2C-43-4E-3D-50-75-62-6C-69-63-25-32-30-4B-65-79-25-32-30-53-65-72-76-69-63-65-73-2C-43-4E-3D-53-65-72-76-69-63-65-73-2C-43-4E-3D-43-6F-6E-66-69-67-75-72-61-74-69-6F-6E-2C-44-43-3D-61-64-2D-6C-61-62-2C-44-43-3D-6C-6F-63-61-6C-3F-63-41-43-65-72-74-69-66-69-63-61-74-65-3F-62-61-73-65-3F-6F-62-6A-65-63-74-43-6C-61-73-73-3D-63-65-72-74-69-66-69-63-61-74-69-6F-6E-41-75-74-68-6F-72-69-74-79-30-45-06-03-55-1D-11-04-3E-30-3C-A0-1F-06-09-2B-06-01-04-01-82-37-19-01-A0-12-04-10-B9-5E-4B-4A-2A-F8-0A-40-9C-22-4F-A0-27-50-77-FA-82-19-41-44-2D-53-65-72-76-65-72-2D-30-31-2E-61-64-2D-6C-61-62-2E-6C-6F-63-61-6C-30-4F-06-09-2B-06-01-04-01-82-37-19-02-04-42-30-40-A0-3E-06-0A-2B-06-01-04-01-82-37-19-02-01-A0-30-04-2E-53-2D-31-2D-35-2D-32-31-2D-31-31-36-36-37-31-37-35-30-34-2D-31-35-32-31-34-30-34-39-36-36-2D-33-38-39-35-38-30-33-38-32-36-2D-31-30-30-30-30-0D-06-09-2A-86-48-86-F7-0D-01-01-0B-05-00-03-82-01-01-00-7E-16-9D-B1-A7-5A-DA-CE-B1-E0-A0-81-4A-D5-7C-1F-AF-31-A2-A0-CF-55-03-19-35-40-32-DF-32-39-2F-CF-A4-30-39-DF-7D-35-AB-A7-3B-2D-EF-D3-24-8F-74-72-4E-AC-6F-8B-19-AE-77-67-43-3B-FD-70-8A-F7-1E-0F-7B-65-08-A6-AC-D4-D3-D9-FA-94-20-93-62-D8-82-7A-C5-22-F0-15-EA-93-3B-4F-D2-9C-8D-EE-48-FB-60-7D-89-2E-62-60-87-C0-87-2C-C0-FE-DB-74-5E-F7-50-AE-B5-90-A3-E0-4A-8D-F3-E4-D0-C0-BA-74-3E-56-46-6D-7B-63-02-A0-B9-81-4B-7D-8F-64-48-57-76-93-65-94-FF-1D-7C-14-2E-99-32-EF-C7-F2-62-29-9A-56-9D-89-CD-F8-AC-52-C5-EE-E5-53-29-62-76-55-E4-D6-5B-80-3A-98-CD-AF-54-F5-13-4F-C6-7A-DE-69-6C-04-02-D5-8A-A3-4B-C7-71-AC-CE-8F-F7-CE-3D-EB-F7-5A-8B-7E-39-54-AA-26-FF-11-92-CE-DC-3C-49-2A-04-AE-27-15-6D-5B-D8-D3-2C-1E-FC-49-33-80-10-66-73-C2-F8-F8-3C-C1-7E-D0-79-92-34-0B-33-10-A8-D3-29-EE-C5-E9"
    let input = Map.ofList [ "usercertificate", [ADBytes cert] ]
    let result = handleUserCertificate input
    // Handler returns 3 strings per cert: Issuer, Subject, PubKey
    
    match Map.tryFind "usercertificate" result with
    | Some vals ->
        Expect.equal (List.length vals) 3 "decoded to 3 strings (issuer, subject, pubkey)"
        
        match List.head vals with
        | ADString s -> Expect.isTrue (s.Length > 0) "decoded to non-empty string"
        | _ -> Expect.isTrue false "expected ADString"
    | _ -> Expect.isTrue false "expected string result"

let ``handles UserCertificate missing`` () =
    let input = Map.ofList [ "cn", [ADString "test"] ]
    let result = handleUserCertificate input
    Expect.isFalse (Map.containsKey "usercertificate" result) "no usercertificate added"

let ``handles NTSecurityDescriptor`` () =
    // Real NTSecurityDescriptor from raw dump (2488 bytes)
    let sdBytes = hexToBytes "01-00-04-84-98-09-00-00-A8-09-00-00-00-00-00-00-14-00-00-00-04-00-84-09-36-00-00-00-01-00-14-00-02-00-00-00-01-01-00-00-00-00-00-01-00-00-00-00-05-0A-3C-00-10-00-00-00-03-00-00-00-00-42-16-4C-C0-20-D0-11-A7-68-00-AA-00-6E-05-29-14-CC-28-48-37-14-BC-45-9B-07-AD-6F-01-5E-5F-28-01-02-00-00-00-00-00-05-20-00-00-00-2A-02-00-00-05-0A-3C-00-10-00-00-00-03-00-00-00-00-42-16-4C-C0-20-D0-11-A7-68-00-AA-00-6E-05-29-BA-7A-96-BF-E6-0D-D0-11-A2-85-00-AA-00-30-49-E2-01-02-00-00-00-00-00-05-20-00-00-00-2A-02-00-00-05-0A-3C-00-10-00-00-00-03-00-00-00-10-20-20-5F-A5-79-D0-11-90-20-00-C0-4F-C2-D4-CF-14-CC-28-48-37-14-BC-45-9B-07-AD-6F-01-5E-5F-28-01-02-00-00-00-00-00-05-20-00-00-00-2A-02-00-00-05-0A-3C-00-10-00-00-00-03-00-00-00-10-20-20-5F-A5-79-D0-11-90-20-00-C0-4F-C2-D4-CF-BA-7A-96-BF-E6-0D-D0-11-A2-85-00-AA-00-30-49-E2-01-02-00-00-00-00-00-05-20-00-00-00-2A-02-00-00-05-0A-3C-00-10-00-00-00-03-00-00-00-40-C2-0A-BC-A9-79-D0-11-90-20-00-C0-4F-C2-D4-CF-14-CC-28-48-37-14-BC-45-9B-07-AD-6F-01-5E-5F-28-01-02-00-00-00-00-00-05-20-00-00-00-2A-02-00-00-05-0A-3C-00-10-00-00-00-03-00-00-00-40-C2-0A-BC-A9-79-D0-11-90-20-00-C0-4F-C2-D4-CF-BA-7A-96-BF-E6-0D-D0-11-A2-85-00-AA-00-30-49-E2-01-02-00-00-00-00-00-05-20-00-00-00-2A-02-00-00-05-0A-3C-00-10-00-00-00-03-00-00-00-42-2F-BA-59-A2-79-D0-11-90-20-00-C0-4F-C2-D3-CF-14-CC-28-48-37-14-BC-45-9B-07-AD-6F-01-5E-5F-28-01-02-00-00-00-00-00-05-20-00-00-00-2A-02-00-00-05-0A-3C-00-10-00-00-00-03-00-00-00-42-2F-BA-59-A2-79-D0-11-90-20-00-C0-4F-C2-D3-CF-BA-7A-96-BF-E6-0D-D0-11-A2-85-00-AA-00-30-49-E2-01-02-00-00-00-00-00-05-20-00-00-00-2A-02-00-00-05-0A-3C-00-10-00-00-00-03-00-00-00-F8-88-70-03-E1-0A-D2-11-B4-22-00-A0-C9-68-F9-39-14-CC-28-48-37-14-BC-45-9B-07-AD-6F-01-5E-5F-28-01-02-00-00-00-00-00-05-20-00-00-00-2A-02-00-00-05-0A-3C-00-10-00-00-00-03-00-00-00-F8-88-70-03-E1-0A-D2-11-B4-22-00-A0-C9-68-F9-39-BA-7A-96-BF-E6-0D-D0-11-A2-85-00-AA-00-30-49-E2-01-02-00-00-00-00-00-05-20-00-00-00-2A-02-00-00-05-00-38-00-00-01-00-00-01-00-00-00-18-7E-0F-3E-7A-2C-10-4C-BA-82-4D-92-6D-B9-9A-3E-01-05-00-00-00-00-00-05-15-00-00-00-40-B2-8A-45-26-CC-AE-5A-B2-3F-35-E8-0A-02-00-00-05-00-38-00-00-01-00-00-01-00-00-00-AA-F6-31-11-07-9C-D1-11-F7-9F-00-C0-4F-C2-DC-D2-01-05-00-00-00-00-00-05-15-00-00-00-40-B2-8A-45-26-CC-AE-5A-B2-3F-35-E8-F2-01-00-00-05-00-38-00-00-01-00-00-01-00-00-00-AD-F6-31-11-07-9C-D1-11-F7-9F-00-C0-4F-C2-DC-D2-01-05-00-00-00-00-00-05-15-00-00-00-40-B2-8A-45-26-CC-AE-5A-B2-3F-35-E8-04-02-00-00-05-02-38-00-30-00-00-00-01-00-00-00-0F-D6-47-5B-90-60-B2-40-9F-37-2A-4D-E8-8F-30-63-01-05-00-00-00-00-00-05-15-00-00-00-40-B2-8A-45-26-CC-AE-5A-B2-3F-35-E8-0E-02-00-00-05-02-38-00-30-00-00-00-01-00-00-00-0F-D6-47-5B-90-60-B2-40-9F-37-2A-4D-E8-8F-30-63-01-05-00-00-00-00-00-05-15-00-00-00-40-B2-8A-45-26-CC-AE-5A-B2-3F-35-E8-0F-02-00-00-05-0A-38-00-08-00-00-00-03-00-00-00-A6-6D-02-9B-3C-0D-5C-46-8B-EE-51-99-D7-16-5C-BA-86-7A-96-BF-E6-0D-D0-11-A2-85-00-AA-00-30-49-E2-01-01-00-00-00-00-00-03-00-00-00-00-05-0A-38-00-08-00-00-00-03-00-00-00-A6-6D-02-9B-3C-0D-5C-46-8B-EE-51-99-D7-16-5C-BA-86-7A-96-BF-E6-0D-D0-11-A2-85-00-AA-00-30-49-E2-01-01-00-00-00-00-00-05-0A-00-00-00-05-0A-38-00-10-00-00-00-03-00-00-00-6D-9E-C6-B7-C7-2C-D2-11-85-4E-00-A0-C9-83-F6-08-86-7A-96-BF-E6-0D-D0-11-A2-85-00-AA-00-30-49-E2-01-01-00-00-00-00-00-05-09-00-00-00-05-0A-38-00-10-00-00-00-03-00-00-00-6D-9E-C6-B7-C7-2C-D2-11-85-4E-00-A0-C9-83-F6-08-9C-7A-96-BF-E6-0D-D0-11-A2-85-00-AA-00-30-49-E2-01-01-00-00-00-00-00-05-09-00-00-00-05-0A-38-00-10-00-00-00-03-00-00-00-6D-9E-C6-B7-C7-2C-D2-11-85-4E-00-A0-C9-83-F6-08-BA-7A-96-BF-E6-0D-D0-11-A2-85-00-AA-00-30-49-E2-01-01-00-00-00-00-00-05-09-00-00-00-05-0A-38-00-20-00-00-00-03-00-00-00-93-7B-1B-EA-48-5E-D5-46-BC-6C-4D-F4-FD-A7-8A-35-86-7A-96-BF-E6-0D-D0-11-A2-85-00-AA-00-30-49-E2-01-01-00-00-00-00-00-05-0A-00-00-00-05-00-2C-00-00-01-00-00-01-00-00-00-76-5B-E9-89-4D-44-62-4C-99-1A-0F-AC-BE-DA-64-0C-01-02-00-00-00-00-00-05-20-00-00-00-20-02-00-00-05-00-2C-00-00-01-00-00-01-00-00-00-AA-F6-31-11-07-9C-D1-11-F7-9F-00-C0-4F-C2-DC-D2-01-02-00-00-00-00-00-05-20-00-00-00-20-02-00-00-05-00-2C-00-00-01-00-00-01-00-00-00-AB-F6-31-11-07-9C-D1-11-F7-9F-00-C0-4F-C2-DC-D2-01-02-00-00-00-00-00-05-20-00-00-00-20-02-00-00-05-00-2C-00-00-01-00-00-01-00-00-00-AC-F6-31-11-07-9C-D1-11-F7-9F-00-C0-4F-C2-DC-D2-01-02-00-00-00-00-00-05-20-00-00-00-20-02-00-00-05-00-2C-00-00-01-00-00-01-00-00-00-AD-F6-31-11-07-9C-D1-11-F7-9F-00-C0-4F-C2-DC-D2-01-02-00-00-00-00-00-05-20-00-00-00-20-02-00-00-05-00-2C-00-00-01-00-00-01-00-00-00-AE-F6-31-11-07-9C-D1-11-F7-9F-00-C0-4F-C2-DC-D2-01-02-00-00-00-00-00-05-20-00-00-00-20-02-00-00-05-00-2C-00-00-01-00-00-01-00-00-00-C9-6D-A3-E2-17-AE-C3-47-B5-8B-BE-34-C5-5B-A6-33-01-02-00-00-00-00-00-05-20-00-00-00-2D-02-00-00-05-00-2C-00-10-00-00-00-01-00-00-00-60-73-40-C7-BF-20-D0-11-A7-68-00-AA-00-6E-05-29-01-02-00-00-00-00-00-05-20-00-00-00-2A-02-00-00-05-00-2C-00-10-00-00-00-01-00-00-00-D0-9F-11-B8-F6-04-62-47-AB-7A-49-86-C7-6B-3F-9A-01-02-00-00-00-00-00-05-20-00-00-00-2A-02-00-00-05-0A-2C-00-94-00-02-00-02-00-00-00-14-CC-28-48-37-14-BC-45-9B-07-AD-6F-01-5E-5F-28-01-02-00-00-00-00-00-05-20-00-00-00-2A-02-00-00-05-0A-2C-00-94-00-02-00-02-00-00-00-9C-7A-96-BF-E6-0D-D0-11-A2-85-00-AA-00-30-49-E2-01-02-00-00-00-00-00-05-20-00-00-00-2A-02-00-00-05-0A-2C-00-94-00-02-00-02-00-00-00-BA-7A-96-BF-E6-0D-D0-11-A2-85-00-AA-00-30-49-E2-01-02-00-00-00-00-00-05-20-00-00-00-2A-02-00-00-05-00-28-00-00-01-00-00-01-00-00-00-5E-4C-C7-05-EB-4D-B4-43-BD-9F-86-66-4C-2A-7F-D5-01-01-00-00-00-00-00-05-0B-00-00-00-05-00-28-00-00-01-00-00-01-00-00-00-76-5B-E9-89-4D-44-62-4C-99-1A-0F-AC-BE-DA-64-0C-01-01-00-00-00-00-00-05-09-00-00-00-05-00-28-00-00-01-00-00-01-00-00-00-7D-DC-C2-CC-AD-A6-7A-4A-88-46-C0-4E-3C-C5-35-01-01-01-00-00-00-00-00-05-0B-00-00-00-05-00-28-00-00-01-00-00-01-00-00-00-9C-36-0F-28-C7-67-8E-43-AE-98-1D-46-F3-C6-F5-41-01-01-00-00-00-00-00-05-0B-00-00-00-05-00-28-00-00-01-00-00-01-00-00-00-AA-F6-31-11-07-9C-D1-11-F7-9F-00-C0-4F-C2-DC-D2-01-01-00-00-00-00-00-05-09-00-00-00-05-00-28-00-00-01-00-00-01-00-00-00-AB-F6-31-11-07-9C-D1-11-F7-9F-00-C0-4F-C2-DC-D2-01-01-00-00-00-00-00-05-09-00-00-00-05-00-28-00-00-01-00-00-01-00-00-00-AC-F6-31-11-07-9C-D1-11-F7-9F-00-C0-4F-C2-DC-D2-01-01-00-00-00-00-00-05-09-00-00-00-05-00-28-00-00-01-00-00-01-00-00-00-AE-F6-31-11-07-9C-D1-11-F7-9F-00-C0-4F-C2-DC-D2-01-01-00-00-00-00-00-05-09-00-00-00-05-00-28-00-10-00-00-00-01-00-00-00-D0-9F-11-B8-F6-04-62-47-AB-7A-49-86-C7-6B-3F-9A-01-01-00-00-00-00-00-05-0B-00-00-00-05-03-28-00-30-00-00-00-01-00-00-00-E5-C3-78-3F-9A-F7-BD-46-A0-B8-9D-18-11-6D-DC-79-01-01-00-00-00-00-00-05-0A-00-00-00-05-0A-28-00-30-01-00-00-01-00-00-00-DE-47-E6-91-6F-D9-70-4B-95-57-D6-3F-F4-F3-CC-D8-01-01-00-00-00-00-00-05-0A-00-00-00-00-00-24-00-BD-01-0E-00-01-05-00-00-00-00-00-05-15-00-00-00-40-B2-8A-45-26-CC-AE-5A-B2-3F-35-E8-00-02-00-00-00-02-24-00-FF-01-0F-00-01-05-00-00-00-00-00-05-15-00-00-00-40-B2-8A-45-26-CC-AE-5A-B2-3F-35-E8-07-02-00-00-00-00-18-00-10-00-02-00-01-02-00-00-00-00-00-05-20-00-00-00-2A-02-00-00-00-02-18-00-04-00-00-00-01-02-00-00-00-00-00-05-20-00-00-00-2A-02-00-00-00-02-18-00-BD-01-0F-00-01-02-00-00-00-00-00-05-20-00-00-00-20-02-00-00-00-00-14-00-10-00-00-00-01-01-00-00-00-00-00-01-00-00-00-00-00-00-14-00-94-00-02-00-01-01-00-00-00-00-00-05-09-00-00-00-00-00-14-00-94-00-02-00-01-01-00-00-00-00-00-05-0B-00-00-00-00-00-14-00-FF-01-0F-00-01-01-00-00-00-00-00-05-12-00-00-00-01-02-00-00-00-00-00-05-20-00-00-00-20-02-00-00-01-02-00-00-00-00-00-05-20-00-00-00-20-02-00-00"
    let input = Map.ofList [ "ntsecuritydescriptor", [ADBytes sdBytes] ]
    let result = handleNtSecurityDescriptor input
    
    match Map.tryFind "ntsecuritydescriptor" result with
    | Some vals ->
        Expect.isTrue (List.length vals > 0) "decoded to non-empty list"
        
        match List.head vals with
        | ADString s -> Expect.isTrue (s.Length > 0) "decoded to non-empty string"
        | _ -> Expect.isTrue false "expected ADString"
    | _ -> Expect.isTrue false "expected string result"

let ``handles NTSecurityDescriptor missing`` () =
    let input = Map.ofList [ "cn", [ADString "test"] ]
    let result = handleNtSecurityDescriptor input
    Expect.isFalse (Map.containsKey "ntsecuritydescriptor" result) "no ntsecuritydescriptor added"

let ``multiple DNS records handled`` () =
    // Multiple AAAA DNS records from raw dump
    let dns1 = hexToBytes "10-00-1C-00-05-08-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-20-01-05-03-BA-3E-00-00-00-00-00-00-00-02-00-30"
    let dns2 = hexToBytes "10-00-1C-00-05-08-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-20-01-05-00-00-2F-00-00-00-00-00-00-00-00-00-0F"
    let input = Map.ofList [ "dnsrecord", [ADBytes dns1; ADBytes dns2] ]
    let result = handleDNSRecord input
    
    match Map.tryFind "dnsrecord" result with
    | Some vals ->
        Expect.equal (List.length vals) 2 "both records preserved"
    | _ -> Expect.isTrue false "expected string results"

let ``byte handlers preserve other keys`` () =
    let input = Map.ofList [
        "cn", [ADString "test"]
        "objectsid", [ADBytes domainSidBytes] ]
    let result = handleObjectSid input
    Expect.isTrue (Map.containsKey "cn" result) "cn preserved"
    Expect.isTrue (Map.containsKey "objectsid" result) "objectsid present"

// ========== String Handler Tests ==========

let ``handles SamAccountType user`` () =
    let input = Map.ofList [ "samaccounttype", ["805306368"] ]
    let result = handleSamAccountType input
    
    match Map.tryFind "samaccounttype" result with
    | Some vals ->
        Expect.isTrue ((List.head vals).Contains("NORMAL_ACCOUNT")) "identifies user account"
    | _ -> Expect.isTrue false "expected string result"

let ``handles SamAccountType group`` () =
    // 268435456 = 0x10000000 = SAM_GROUP_OBJECT (not SAM_ALIAS_OBJECT)
    let input = Map.ofList [ "samaccounttype", ["268435456"] ]
    let result = handleSamAccountType input
    
    match Map.tryFind "samaccounttype" result with
    | Some vals ->
        Expect.isTrue ((List.head vals).Contains("SAM_GROUP_OBJECT")) "identifies group"
    | _ -> Expect.isTrue false "expected string result"

let ``handles SamAccountType missing`` () =
    let input = Map.ofList [ "cn", ["test"] ]
    let result = handleSamAccountType input
    Expect.isFalse (Map.containsKey "samaccounttype" result) "no samaccounttype added"

let ``handles SystemFlags`` () =
    // Real value from raw dump: -1946157056 (0x8C000000) = CANNOT_BE_DELETED | CANNOT_BE_MOVED | CANNOT_BE_RENAMED
    let input = Map.ofList [ "systemflags", ["-1946157056"] ]
    let result = handleSystemFlags input
    
    match Map.tryFind "systemflags" result with
    | Some vals ->
        Expect.isTrue (List.exists (fun (s: string) -> s.Contains("CANNOT_BE_DELETED")) vals) "identifies CANNOT_BE_DELETED flag"
    | _ -> Expect.isTrue false "expected string result"

let ``handles SystemFlags missing`` () =
    let input = Map.ofList [ "cn", ["test"] ]
    let result = handleSystemFlags input
    Expect.isFalse (Map.containsKey "systemflags" result) "no systemflags added"

let ``handles TrustDirection OUTBOUND`` () =
    let input = Map.ofList [ "trustdirection", ["2"] ]
    let result = handleTrustDirection input
    
    match Map.tryFind "trustdirection" result with
    | Some vals ->
        Expect.equal (List.head vals) "TRUST_DIRECTION_OUTBOUND" "correct direction"
    | _ -> Expect.isTrue false "expected string result"

let ``handles TrustDirection INBOUND`` () =
    let input = Map.ofList [ "trustdirection", ["1"] ]
    let result = handleTrustDirection input
    
    match Map.tryFind "trustdirection" result with
    | Some vals ->
        Expect.equal (List.head vals) "TRUST_DIRECTION_INBOUND" "correct direction"
    | _ -> Expect.isTrue false "expected string result"

let ``handles TrustDirection missing`` () =
    let input = Map.ofList [ "cn", ["test"] ]
    let result = handleTrustDirection input
    Expect.isFalse (Map.containsKey "trustdirection" result) "no trustdirection added"

let ``handles TrustType WINDOWS`` () =
    let input = Map.ofList [ "trusttype", ["2"] ]
    let result = handleTrustType input
    
    match Map.tryFind "trusttype" result with
    | Some vals ->
        Expect.equal (List.head vals) "TRUST_TYPE_UPLEVEL" "correct type"
    | _ -> Expect.isTrue false "expected string result"

let ``handles TrustType missing`` () =
    let input = Map.ofList [ "cn", ["test"] ]
    let result = handleTrustType input
    Expect.isFalse (Map.containsKey "trusttype" result) "no trusttype added"

let ``handles TrustAttributes NON_TRANSITIVE`` () =
    let input = Map.ofList [ "trustattributes", ["1"] ]
    let result = handleTrustAttibutes input
    
    match Map.tryFind "trustattributes" result with
    | Some vals ->
        Expect.equal (List.head vals) "TRUST_ATTRIBUTE_NON_TRANSITIVE" "correct attribute"
    | _ -> Expect.isTrue false "expected string result"

let ``handles TrustAttributes missing`` () =
    let input = Map.ofList [ "cn", ["test"] ]
    let result = handleTrustAttibutes input
    Expect.isFalse (Map.containsKey "trustattributes" result) "no trustattributes added"

let ``handles WellKnownThings`` () =
    // Real wellKnownObjects from raw dump
    let wellKnown = "B:32:6227F0AF-1FC2-410D-8E3B-B10615BB5B0F:CN=NTDS Quotas,DC=ad-lab,DC=local"
    let input = Map.ofList [ "wellknownobjects", [wellKnown] ]
    let result = handleWellKnownThings input
    
    match Map.tryFind "wellknownobjects" result with
    | Some vals ->
        Expect.isTrue ((List.head vals).Contains("NTDS Quotas")) "decoded well-known object"
    | _ -> Expect.isTrue false "expected string result"

let ``handles WellKnownThings missing`` () =
    let input = Map.ofList [ "cn", ["test"] ]
    let result = handleWellKnownThings input
    Expect.isFalse (Map.containsKey "wellknownobjects" result) "no wellknownobjects added"

let allTests =
    testList "Byte and String Handlers" 
        [ testCase "handles SID objectsid" ``handles SID objectsid``
          testCase "handles SID objectsid missing" ``handles SID objectsid missing``
          testCase "handles ObjectGUID" ``handles ObjectGUID``
          testCase "handles ObjectGUID missing" ``handles ObjectGUID missing``
          testCase "handles msds-optionalfeatureguid single" ``handles msds-optionalfeatureguid single``
          testCase "handles msds-optionalfeatureguid multiple" ``handles msds-optionalfeatureguid multiple``
          testCase "handles msds-optionalfeatureguid missing" ``handles msds-optionalfeatureguid missing``
          testCase "handles DNS record" ``handles DNS record``
          testCase "handles DNS record missing" ``handles DNS record missing``
          testCase "handles DSA signature" ``handles DSA signature``
          testCase "handles DSA signature missing" ``handles DSA signature missing``
          testCase "handles UserCertificate" ``handles UserCertificate``
          testCase "handles UserCertificate missing" ``handles UserCertificate missing``
          testCase "handles NTSecurityDescriptor" ``handles NTSecurityDescriptor``
          testCase "handles NTSecurityDescriptor missing" ``handles NTSecurityDescriptor missing``
          testCase "multiple DNS records handled" ``multiple DNS records handled``
          testCase "byte handlers preserve other keys" ``byte handlers preserve other keys``
          testCase "handles SamAccountType user" ``handles SamAccountType user``
          testCase "handles SamAccountType group" ``handles SamAccountType group``
          testCase "handles SamAccountType missing" ``handles SamAccountType missing``
          testCase "handles SystemFlags" ``handles SystemFlags``
          testCase "handles SystemFlags missing" ``handles SystemFlags missing``
          testCase "handles TrustDirection OUTBOUND" ``handles TrustDirection OUTBOUND``
          testCase "handles TrustDirection INBOUND" ``handles TrustDirection INBOUND``
          testCase "handles TrustDirection missing" ``handles TrustDirection missing``
          testCase "handles TrustType WINDOWS" ``handles TrustType WINDOWS``
          testCase "handles TrustType missing" ``handles TrustType missing``
          testCase "handles TrustAttributes NON_TRANSITIVE" ``handles TrustAttributes NON_TRANSITIVE``
          testCase "handles TrustAttributes missing" ``handles TrustAttributes missing``
          testCase "handles WellKnownThings" ``handles WellKnownThings``
          testCase "handles WellKnownThings missing" ``handles WellKnownThings missing`` ]
