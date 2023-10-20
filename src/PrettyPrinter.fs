namespace Fiewport


open System
open Spectre.Console
open SpectreCoff

[<AutoOpen>]
module PrettyPrinter =
    
    let private panelFormat =
        { defaultPanelLayout with
            Sizing = SizingBehaviour.Expand
            BorderColor = Some Color.White
            Padding = Padding.AllEqual 0 }

    
    
    
    let private printFormatter key (datum: ADDataTypes) =
        match datum with
        | ADBool x ->
             node ([MC (Color.Blue, $"{key}: "); MC (Color.White, $"{x}")] |> Many) []
        | ADString x ->
             node ([MC (Color.Blue, $"{key}(string): "); MC (Color.White, $"{x}")] |> Many) []
        | ADInt x ->
            node ([MC (Color.Blue, $"{key}(int): "); MC (Color.White, $"{x}")] |> Many) []
        | ADInt64 x ->
            node ([MC (Color.Blue, $"{key}(int64): "); MC (Color.White, $"{x}")] |> Many) []
        | ADBytes x ->
            node ([MC (Color.Grey, $"{key}(bytes): "); MC (Color.White, $"{x |> BitConverter.ToString |> String.filter(fun p -> p <> '-')}") ] |> Many) []
        | ADDateTime x ->
            node ([MC (Color.Blue, $"{key}:"); MC (Color.White, $"{x.ToShortDateString ()}")] |> Many) []
        | ADStrings x ->
            node ([MC (Color.Blue, $"{key}(strings):")] |> Many) [ for item in x do yield node ([MC (Color.White, $"{item}")] |> Many) [] ]
        | ADBytesList x ->
            node ([MC (Color.Blue, $"{key}(byte array list):")] |> Many) [ for item in x do yield node ([MC (Color.White, $"{item |> BitConverter.ToString |> String.filter(fun p -> p <> '-')}")] |> Many) [] ]
        | ADDateTimes x ->
            node ([MC (Color.Blue, $"{key}:")] |> Many) [for item in x do yield node (MC (Color.White, $"{item.ToShortDateString ()}")) []]  
    
    let private printer (mbox: MailboxProcessor<LDAPSearchResult>) =
        
        let rec ringRing () = async {
            let! msg = mbox.Receive ()
            let keys = [for key in msg.lDAPData.Keys do yield key]
            let _data = keys |> List.map (fun key -> key, msg.lDAPData[key])
            
            let domainComponent =
                msg.objectCategory.Split ',' |> Array.filter (fun p -> p.StartsWith("DC=")) |> String.concat ","
            let containers =
                msg.objectCategory.Split ',' |> Array.filter (fun p -> p.StartsWith("CN=")) |> String.concat ","
            
            [ MC (Color.Gold1, $"Object Category: {containers}"); NL
              MC (Color.Grey, $"Domain Components: {domainComponent}"); NL
              MC (Color.Gold1, $"""Object Classes: {msg.objectClass |> String.concat ", "}"""); NL
              MC (Color.Wheat1, $"objectGUID: {msg.objectGUID}"); NL
              tree (V "attributes") (_data |> List.map (fun (key, datum) -> printFormatter key datum)) ]
            |> Many
            |> toConsole
            
            do! ringRing ()
        }

        ringRing ()
        
    let private pPrinter =
        // Stupid bodge to deal with nonsense. Spectre will not emit any markup text 
        // from inside the MailboxProcessor without first printing it _outside_ the mailbox.
        // It doesn't make any sense. So I print a black line. 🙄🙄
        Many [MC (Color.Black, "")] |> toConsole       
        MailboxProcessor.Start printer
        
    
    let public prettyPrint (res: LDAPSearchResult list) =
        res |> List.iter (fun r ->
            pPrinter.Post r
            // I have to sleep here because otherwise the main thread risks exiting before the printer prints.
            // I tried forcing synchronous execution, but that didn't seem to do anything at all about the issue.
            System.Threading.Thread.Sleep 4) 
        