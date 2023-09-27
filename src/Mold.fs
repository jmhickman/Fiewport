namespace Fiewport

open Types

module Mold =
    
    type Mold = class end
    
        with        
        
        static member getValue key (res: LDAPSearchResult list) =
            List.map (fun r -> r.LDAPData[key]) res

