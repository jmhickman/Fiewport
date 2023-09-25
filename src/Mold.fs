namespace Fiewport

open Types

module Mold =
    
    type Mold = class end
    
        with        
        
        static member getValue key (res: LDAPSearchResult) =
            res.LDAPData[key]

