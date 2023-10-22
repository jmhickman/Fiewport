namespace Fiewport

open Types
open LDAPConstants
open System
open System.Security.Cryptography.X509Certificates
open System.Security.AccessControl
open System.Security.Principal

[<AutoOpen>]
module ADData =
     
    let private getAccessFlags accessMask =
        activeDirectoryRightsList
        |> List.filter (fun enum -> (accessMask &&& int enum) = int enum)
        |> List.map (fun enum -> enum.ToString())
        |> String.concat ", "


    let private matchKnownSids sid =        
        if wellKnownSids.ContainsKey sid then wellKnownSids[sid]
        else if networkSids.ContainsKey (sid.Split '-' |> Array.last) then networkSids[sid.Split '-' |> Array.last]
        else sid

    ///
    /// <summary>
    /// An object that collects some static methods for working with ADDataTypes.
    /// </summary>
    /// <remarks>
    /// These have no type safety or checking. If you feed a string into an Int unwrapper,
    /// you're just going to get a 0. If you feed in a malformed SDDL byte array, it will blow up. And so on.
    /// </remarks>
    /// 
    type ADData = class end
         with
         
         static member public unwrapADInt64 adInt64 =
             match adInt64 with
             | ADInt64 x -> x
             | _ -> 0L


         static member public unwrapADInt adInt =
             match adInt with
             | ADInt x -> x
             | _ -> 0


         static member public unwrapADBytes adBytes =
             match adBytes with
             | ADBytes x -> x
             | _ -> [||]


         static member public unwrapADString adString =
             match adString with
             | ADString x -> x
             | _ -> ""


         static member public unwrapADDateTime adDateTime =
             match adDateTime with
             | ADDateTime x -> x
             | _ -> DateTime.UnixEpoch


         static member public unwrapADStrings adStrings =
             match adStrings with
             | ADStringList x -> x
             | _ -> [""]


         static member public unwrapADDateTimes unwrapADDateTime =
             match unwrapADDateTime with
             | ADDateTimeList x -> x
             | _ -> [DateTime.UnixEpoch]


         static member internal readSecurityDescriptor bytes =
            let getSIDAndFlags (genAce: GenericAce) =
                genAce :?> CommonAce // yolo, works on my AD, etc
                |> fun comAce -> $"{matchKnownSids comAce.SecurityIdentifier.Value}::{getAccessFlags comAce.AccessMask}"
            
            let descriptor = CommonSecurityDescriptor(false, false, bytes, 0)
            let humanDACLs = [for dacl in descriptor.DiscretionaryAcl do yield dacl] |> List.map getSIDAndFlags
                
            { owner = descriptor.Owner.Value
              group = descriptor.Group.Value
              dacl = humanDACLs }


         static member internal readUserAccountControl bits =
             [for i in 0..31 do if ((bits >>> i) &&& 1) = 1 then yield uacPropertyFlags[i]]


         static member internal readSID bytes =
             SecurityIdentifier(bytes, 0) |> fun sid -> sid.Value


         static member internal readmsDSSupportedEncryptionTypes bits =
             msdsSupportedEncryptionTypes[bits]


         static member internal readX509Cert (certBytes: byte array) =
             let cert = new X509Certificate(certBytes)
             let stringify = $"{cert.Issuer}", $"{cert.Subject}", $"0x{cert.GetPublicKey () |> BitConverter.ToString |> String.filter(fun p -> p <> '-')}"
             cert.Dispose ()
             stringify
