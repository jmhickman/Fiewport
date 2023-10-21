namespace Fiewport

open Types
open LDAPConstants
open System
open System.Security.AccessControl
open System.Security.Principal

[<AutoOpen>]
module ADData =
    
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
         
         static member unwrapADInt64 adInt64 =
             match adInt64 with
             | ADInt64 x -> x
             | _ -> 0L
             
         static member unwrapADInt adInt =
             match adInt with
             | ADInt x -> x
             | _ -> 0
             
         static member unwrapADBytes adBytes =
             match adBytes with
             | ADBytes x -> x
             | _ -> [||]
             
         static member unwrapADString adString =
             match adString with
             | ADString x -> x
             | _ -> ""
             
         static member unwrapADDateTime adDateTime =
             match adDateTime with
             | ADDateTime x -> x
             | _ -> DateTime.UnixEpoch
         
         static member unwrapADStrings adStrings =
             match adStrings with
             | ADStrings x -> x
             | _ -> [""]
             
         static member unwrapADDateTimes unwrapADDateTime =
             match unwrapADDateTime with
             | ADDateTimes x -> x
             | _ -> [DateTime.UnixEpoch]

         static member readSecurityDescriptor bytes =
            let rdr = RawSecurityDescriptor(bytes, 0)
            rdr.GetSddlForm(AccessControlSections.All)
            
         static member readUserAccountControl bits =
             [for i in 0..31 do if ((bits >>> i) &&& 1) = 1 then yield uacPropertyFlags[i]]
            
             
         static member readSID bytes =
             SecurityIdentifier(bytes, 0) |> fun sid -> sid.Value
             
             
         static member readmsDSSupportedEncryptionTypes bits =
             msdsSupportedEncryptionTypes[bits]