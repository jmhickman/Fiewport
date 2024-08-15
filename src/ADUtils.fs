namespace Fiewport

open Types
open LDAPConstants
open System
open System.Security.Cryptography.X509Certificates
open System.Security.AccessControl
open System.Security.Principal

[<AutoOpen>]
module ADUtils =
     



    let internal matchKnownSids sid =        
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

         static member public unwrapADBytes adBytes =
             match adBytes with
             | ADBytes x -> x
             | _ -> [||]

         static member public unwrapADString adString =
             match adString with
             | ADString x -> x
             | _ -> ""


         


         static member internal readSecurityDescriptor bytes =
            let descriptor = CommonSecurityDescriptor(false, false, bytes, 0) // need to check into these flags to make sure I'm not reading these incorrectly
            let humanDACLs = 
                [for dacl in descriptor.DiscretionaryAcl do yield dacl]
                |> List.map (fun dacl ->
                    match dacl with
                    | :? CommonAce as common ->
                        let flags = getAccessFlags common.AccessMask
                        $"{matchKnownSids common.SecurityIdentifier.Value}--{flags}"
                    | _ -> "")
                |> List.filter (fun p -> p <> "")
                
            { owner = descriptor.Owner.Value
              group = descriptor.Group.Value
              dacl = humanDACLs }


         static member internal readUserAccountControl bits =
             [for i in 0..31 do if ((bits >>> i) &&& 1) = 1 then yield uacPropertyFlags[i]]


         static member internal readSID bytes =
             SecurityIdentifier(bytes, 0) |> _.Value


         static member internal readmsDSSupportedEncryptionTypes bits =
             msdsSupportedEncryptionTypes[bits]


         static member internal readX509Cert (certBytes: byte array) =
             let cert = new X509Certificate(certBytes)
             let stringify = $"{cert.Issuer}", $"{cert.Subject}", $"0x{cert.GetPublicKey () |> BitConverter.ToString |> String.filter(fun p -> p <> '-')}"
             cert.Dispose ()
             stringify // TODO: should I be returning a tuple? Maybe check the caller on this
