module DetoXSS.Sanitize exposing
    ( encodeHtml
    , decodeBasicEntities
    , sanitizeText
    , sanitizeForAttribute
    , sanitizeWithWhitelist
    , stripControl
    )

{- | A module for sanitizing HTML content and attributes to prevent XSS vulnerabilities. It includes functions for encoding HTML entities, decoding basic entities, stripping control characters, and sanitizing text and attributes based on a whitelist configuration. -}

import Char
import DetoXSS.Core exposing (SafeHtml, ValidatedInput, fromSanitized, fromValidated)
import DetoXSS.Whitelist as WL


encodeHtml : String -> String
encodeHtml s =
    let
        step : Char -> String -> String
        step c acc =
            case c of
                '<' ->
                    "&lt;" ++ acc

                '>' ->
                    "&gt;" ++ acc

                '&' ->
                    "&amp;" ++ acc

                '"' ->
                    "&quot;" ++ acc

                '\'' ->
                    "&#39;" ++ acc

                _ ->
                    String.fromChar c ++ acc
    in
    String.foldr step "" s


decodeBasicEntities : String -> String
decodeBasicEntities s =
    s
        |> String.replace "&lt;" "<"
        |> String.replace "&gt;" ">"
        |> String.replace "&amp;" "&"
        |> String.replace "&quot;" "\""
        |> String.replace "&#39;" "'"
        |> String.replace "&#47;" "/"


sanitizeText : String -> SafeHtml
sanitizeText raw =
    raw
        |> decodeBasicEntities
        |> stripControl
        |> encodeHtml
        |> fromSanitized


sanitizeForAttribute : String -> ValidatedInput
sanitizeForAttribute v =
    v
        |> stripControl
        |> collapseWs
        |> fromValidated


stripControl : String -> String
stripControl =
    String.filter
        (\c ->
            let
                n =
                    Char.toCode c
            in
            n >= 32 || c == '\n' || c == '\r' || c == '\t'
        )


collapseWs : String -> String
collapseWs s =
    s
        |> String.words
        |> String.join " "


-- Sanitizer-specific normalization
--
-- The sanitizer must not blindly normalize the whole document as if it was a
-- browser parser. That could turn harmless text into markup. We therefore use
-- two levels of normalization:
--   * decodeForHtmlStructure decodes HTML entities before tokenization, so
--     encoded tags such as &lt;script&gt; or &#x3c;script&#x3e; are sanitized as tags.
--   * decodeForUrlCheck is stronger and is used only for URL-like attributes
--     before checking the scheme. This catches obfuscated schemes such as
--     java&#x0A;script:, java%0Ascript:, jav\x61script:, or \6a avascript:.


decodeForHtmlStructure : String -> String
decodeForHtmlStructure raw =
    raw
        |> decodeHtmlEntityRepeated 3


decodeForAttributeValue : String -> String
decodeForAttributeValue raw =
    raw
        |> decodeHtmlEntityRepeated 3


decodeForUrlCheck : String -> String
decodeForUrlCheck raw =
    raw
        |> decodeRepeatedForUrl 4
        |> removeSchemeInvisibleChars


decodeRepeatedForUrl : Int -> String -> String
decodeRepeatedForUrl n raw =
    if n <= 0 then
        raw

    else
        let
            next =
                raw
                    |> stripNullBytes
                    |> decodeHtmlEntityOnce
                    |> decodeUnicodeEscapesStr
                    |> decodeHexEscapesStr
                    |> decodeJsOctalEscapesStr
                    |> decodeCssEscapesStr
                    |> decodeUrlEncodedStr
        in
        if next == raw then
            raw

        else
            decodeRepeatedForUrl (n - 1) next


decodeHtmlEntityRepeated : Int -> String -> String
decodeHtmlEntityRepeated n raw =
    if n <= 0 then
        raw

    else
        let
            next =
                decodeHtmlEntityOnce raw
        in
        if next == raw then
            raw

        else
            decodeHtmlEntityRepeated (n - 1) next


decodeHtmlEntityOnce : String -> String
decodeHtmlEntityOnce raw =
    raw
        |> decodeHtmlNamedEntities
        |> decodeNumericEntitiesSimple


decodeHtmlNamedEntities : String -> String
decodeHtmlNamedEntities src =
    src
        |> decodeBasicEntities
        |> String.replace "&sol;" "/"
        |> String.replace "&num;" "#"
        |> String.replace "&colon;" ":"
        |> String.replace "&colon" ":"
        |> String.replace "&lpar;" "("
        |> String.replace "&rpar;" ")"
        |> String.replace "&equals;" "="
        |> String.replace "&comma;" ","
        |> String.replace "&period;" "."
        |> String.replace "&semi;" ";"
        |> String.replace "&apos;" "'"
        |> String.replace "&NewLine;" "\n"
        |> String.replace "&Tab;" "\t"


decodeNumericEntitiesSimple : String -> String
decodeNumericEntitiesSimple src =
    decodeNumHelp (String.toList src) []


decodeNumHelp : List Char -> List Char -> String
decodeNumHelp remaining acc =
    case remaining of
        [] ->
            String.fromList (List.reverse acc)

        '&' :: '#' :: 'x' :: rest ->
            let
                ( hexChars, after ) =
                    collectAlphaNum rest []
            in
            case after of
                ';' :: afterSemi ->
                    case hexToIntStr (String.fromList hexChars) of
                        Just code ->
                            decodeNumHelp afterSemi (Char.fromCode code :: acc)

                        Nothing ->
                            decodeNumHelp rest (List.reverse (String.toList "&#x") ++ acc)

                _ ->
                    if not (List.isEmpty hexChars) then
                        case hexToIntStr (String.fromList hexChars) of
                            Just code ->
                                decodeNumHelp after (Char.fromCode code :: acc)

                            Nothing ->
                                decodeNumHelp rest (List.reverse (String.toList "&#x") ++ acc)

                    else
                        decodeNumHelp rest (List.reverse (String.toList "&#x") ++ acc)

        '&' :: '#' :: rest ->
            let
                ( decChars, after ) =
                    collectAlphaNum rest []
            in
            case after of
                ';' :: afterSemi ->
                    case String.toInt (String.fromList decChars) of
                        Just code ->
                            decodeNumHelp afterSemi (Char.fromCode code :: acc)

                        Nothing ->
                            decodeNumHelp rest (List.reverse (String.toList "&#") ++ acc)

                _ ->
                    if not (List.isEmpty decChars) then
                        case String.toInt (String.fromList decChars) of
                            Just code ->
                                decodeNumHelp after (Char.fromCode code :: acc)

                            Nothing ->
                                decodeNumHelp rest (List.reverse (String.toList "&#") ++ acc)

                    else
                        decodeNumHelp rest (List.reverse (String.toList "&#") ++ acc)

        c :: rest ->
            decodeNumHelp rest (c :: acc)


collectAlphaNum : List Char -> List Char -> ( List Char, List Char )
collectAlphaNum remaining acc =
    case remaining of
        [] ->
            ( List.reverse acc, [] )

        c :: rest ->
            if Char.isAlphaNum c then
                collectAlphaNum rest (c :: acc)

            else
                ( List.reverse acc, c :: rest )


stripNullBytes : String -> String
stripNullBytes src =
    src
        |> String.replace "\u{0000}" ""
        |> String.replace "&#0;" ""
        |> String.replace "&#00;" ""
        |> String.replace "&#000;" ""
        |> String.replace "&#x0;" ""
        |> String.replace "&#x00;" ""
        |> String.replace "%00" ""
        |> String.replace "\u{200B}" ""
        |> String.replace "\u{200C}" ""
        |> String.replace "\u{200D}" ""
        |> String.replace "\u{FEFF}" ""


removeSchemeInvisibleChars : String -> String
removeSchemeInvisibleChars raw =
    let
        step c acc =
            if isZeroWidth c then
                acc

            else
                c :: acc
    in
    raw
        |> String.toList
        |> List.foldr step []
        |> String.fromList


isControlOrWhitespace : Char -> Bool
isControlOrWhitespace c =
    let
        code =
            Char.toCode c
    in
    code <= 32 || code == 127


isZeroWidth : Char -> Bool
isZeroWidth c =
    c == '\u{200B}'
        || c == '\u{200C}'
        || c == '\u{200D}'
        || c == '\u{FEFF}'


decodeUnicodeEscapesStr : String -> String
decodeUnicodeEscapesStr src =
    decodeUniHelp (String.toList src) []


decodeUniHelp : List Char -> List Char -> String
decodeUniHelp remaining acc =
    case remaining of
        [] ->
            String.fromList (List.reverse acc)

        '\\' :: 'u' :: h1 :: h2 :: h3 :: h4 :: rest ->
            case hexToIntStr (String.fromList [ h1, h2, h3, h4 ]) of
                Just code ->
                    decodeUniHelp rest (Char.fromCode code :: acc)

                Nothing ->
                    decodeUniHelp (h1 :: h2 :: h3 :: h4 :: rest) ('u' :: '\\' :: acc)

        c :: rest ->
            decodeUniHelp rest (c :: acc)


decodeHexEscapesStr : String -> String
decodeHexEscapesStr src =
    decodeHxHelp (String.toList src) []


decodeHxHelp : List Char -> List Char -> String
decodeHxHelp remaining acc =
    case remaining of
        [] ->
            String.fromList (List.reverse acc)

        '\\' :: 'x' :: h1 :: h2 :: rest ->
            case hexToIntStr (String.fromList [ h1, h2 ]) of
                Just code ->
                    decodeHxHelp rest (Char.fromCode code :: acc)

                Nothing ->
                    decodeHxHelp (h1 :: h2 :: rest) ('x' :: '\\' :: acc)

        c :: rest ->
            decodeHxHelp rest (c :: acc)


decodeJsOctalEscapesStr : String -> String
decodeJsOctalEscapesStr src =
    decodeJsOctalHelp (String.toList src) []


decodeJsOctalHelp : List Char -> List Char -> String
decodeJsOctalHelp remaining acc =
    case remaining of
        [] ->
            String.fromList (List.reverse acc)

        '\\' :: rest ->
            let
                ( octalChars, afterOctal ) =
                    takeUpTo3Octal rest []
            in
            if List.isEmpty octalChars then
                decodeJsOctalHelp rest ('\\' :: acc)

            else
                case octalToIntStr (String.fromList octalChars) of
                    Just code ->
                        decodeJsOctalHelp afterOctal (Char.fromCode code :: acc)

                    Nothing ->
                        decodeJsOctalHelp rest ('\\' :: acc)

        c :: rest ->
            decodeJsOctalHelp rest (c :: acc)


takeUpTo3Octal : List Char -> List Char -> ( List Char, List Char )
takeUpTo3Octal remaining acc =
    if List.length acc >= 3 then
        ( List.reverse acc, remaining )

    else
        case remaining of
            [] ->
                ( List.reverse acc, [] )

            c :: rest ->
                if isOctalChar c then
                    takeUpTo3Octal rest (c :: acc)

                else
                    ( List.reverse acc, remaining )


isOctalChar : Char -> Bool
isOctalChar c =
    c >= '0' && c <= '7'


octalToIntStr : String -> Maybe Int
octalToIntStr s =
    String.toList s
        |> List.foldl
            (\c maybeAcc ->
                case maybeAcc of
                    Nothing ->
                        Nothing

                    Just acc ->
                        if isOctalChar c then
                            Just (acc * 8 + Char.toCode c - Char.toCode '0')

                        else
                            Nothing
            )
            (Just 0)


decodeCssEscapesStr : String -> String
decodeCssEscapesStr src =
    decodeCssEscapesHelp (String.toList src) []


decodeCssEscapesHelp : List Char -> List Char -> String
decodeCssEscapesHelp remaining acc =
    case remaining of
        [] ->
            String.fromList (List.reverse acc)

        '\\' :: rest ->
            let
                ( hexChars, afterHex ) =
                    takeUpTo6Hex rest []

                afterOptionalSpace =
                    case afterHex of
                        c :: more ->
                            if isCssEscapeWhitespace c then
                                more

                            else
                                afterHex

                        [] ->
                            []
            in
            if List.isEmpty hexChars then
                decodeCssEscapesHelp rest ('\\' :: acc)

            else
                case hexToIntStr (String.fromList hexChars) of
                    Just code ->
                        decodeCssEscapesHelp afterOptionalSpace (Char.fromCode code :: acc)

                    Nothing ->
                        decodeCssEscapesHelp rest ('\\' :: acc)

        c :: rest ->
            decodeCssEscapesHelp rest (c :: acc)


takeUpTo6Hex : List Char -> List Char -> ( List Char, List Char )
takeUpTo6Hex remaining acc =
    if List.length acc >= 6 then
        ( List.reverse acc, remaining )

    else
        case remaining of
            [] ->
                ( List.reverse acc, [] )

            c :: rest ->
                if isHexChar c then
                    takeUpTo6Hex rest (c :: acc)

                else
                    ( List.reverse acc, remaining )


isCssEscapeWhitespace : Char -> Bool
isCssEscapeWhitespace c =
    c == ' '
        || c == '\t'
        || c == '\n'
        || c == '\r'
        || c == '\u{000C}'


decodeUrlEncodedStr : String -> String
decodeUrlEncodedStr src =
    decodeUrlHelp2 (String.toList src) []


decodeUrlHelp2 : List Char -> List Char -> String
decodeUrlHelp2 remaining acc =
    case remaining of
        [] ->
            String.fromList (List.reverse acc)

        '%' :: h1 :: h2 :: rest ->
            case hexToIntStr (String.fromList [ h1, h2 ]) of
                Just code ->
                    if (code >= 0x20 && code <= 0x7E) || code == 0x09 || code == 0x0A || code == 0x0B || code == 0x0C || code == 0x0D then
                        decodeUrlHelp2 rest (Char.fromCode code :: acc)

                    else
                        decodeUrlHelp2 (h1 :: h2 :: rest) ('%' :: acc)

                Nothing ->
                    decodeUrlHelp2 (h1 :: h2 :: rest) ('%' :: acc)

        c :: rest ->
            decodeUrlHelp2 rest (c :: acc)


isHexChar : Char -> Bool
isHexChar c =
    (c >= '0' && c <= '9')
        || (c >= 'a' && c <= 'f')
        || (c >= 'A' && c <= 'F')


hexToIntStr : String -> Maybe Int
hexToIntStr s =
    String.toList (String.toLower s)
        |> List.foldl
            (\c maybeAcc ->
                case maybeAcc of
                    Nothing ->
                        Nothing

                    Just acc ->
                        case hexCharToIntLocal c of
                            Just d ->
                                Just (acc * 16 + d)

                            Nothing ->
                                Nothing
            )
            (Just 0)


hexCharToIntLocal : Char -> Maybe Int
hexCharToIntLocal c =
    if c >= '0' && c <= '9' then
        Just (Char.toCode c - Char.toCode '0')

    else if c >= 'a' && c <= 'f' then
        Just (Char.toCode c - Char.toCode 'a' + 10)

    else
        Nothing


sanitizeWithWhitelist : WL.State -> String -> SafeHtml
sanitizeWithWhitelist state raw =
    if WL.isEnabled state then
        let
            decodedInput =
                raw
                    |> stripControl
                    |> decodeForHtmlStructure

            tokens =
                tokenize decodedInput

            cleanedTokens =
                clean state.config tokens

            renderedHtml =
                render cleanedTokens
        in
        fromSanitized renderedHtml

    else
        sanitizeText raw



type Token
    = TText String
    | TStart String (List ( String, String )) Bool
    | TEnd String


tokenize : String -> List Token
tokenize s =
    tokenizeLoop s []


findTagEnd : String -> Maybe Int
findTagEnd s =
    let
        len =
            String.length s

        loop : Int -> Bool -> String -> Maybe Int
        loop i inQuotes quoteChar =
            if i >= len then
                Nothing

            else
                let
                    ch =
                        String.slice i (i + 1) s
                in
                if inQuotes then
                    if ch == quoteChar then
                        loop (i + 1) False ""

                    else
                        loop (i + 1) True quoteChar

                else if ch == "\"" || ch == "'" then
                    loop (i + 1) True ch

                else if ch == ">" then
                    Just i

                else
                    loop (i + 1) False ""
    in
    loop 0 False ""


tokenizeLoop : String -> List Token -> List Token
tokenizeLoop src acc =
    case findChar '<' src of
        Nothing ->
            if src == "" then
                List.reverse acc

            else
                List.reverse (TText src :: acc)

        Just i ->
            let
                before =
                    String.left i src

                afterLt =
                    String.dropLeft i src
            in
            case findTagEnd afterLt of
                Nothing ->
                    List.reverse (TText src :: acc)

                Just j ->
                    let
                        inside =
                            afterLt
                                |> String.slice 1 j
                                |> String.trim

                        rest =
                            String.dropLeft (j + 1) afterLt

                        toks =
                            if String.startsWith "!" inside then
                                if before == "" then
                                    []

                                else
                                    [ TText before ]

                            else
                                parseTag before inside
                    in
                    tokenizeLoop rest (List.reverse toks ++ acc)


parseTag : String -> String -> List Token
parseTag before inside =
    if String.startsWith "/" inside then
        let
            nm =
                inside
                    |> String.dropLeft 1
                    |> takeName
                    |> normalizeTag
        in
        (if before == "" then
            []

         else
            [ TText before ]
        )
            ++ [ TEnd nm ]

    else
        let
            ( nmRaw, rest1 ) =
                splitName inside

            nm =
                normalizeTag nmRaw

            ( attrs, selfClosing ) =
                parseAttrsAndSelf rest1
        in
        (if before == "" then
            []

         else
            [ TText before ]
        )
            ++ [ TStart nm attrs selfClosing ]


takeName : String -> String
takeName s =
    s
        |> String.trim
        |> String.split " "
        |> List.head
        |> Maybe.withDefault ""


splitName : String -> ( String, String )
splitName s =
    let
        trimmed =
            String.trim s

        len =
            String.length trimmed

        go : Int -> Int
        go idx =
            if idx >= len then
                len

            else
                let
                    c =
                        String.slice idx (idx + 1) trimmed
                in
                if c == " " || c == "/" || c == ">" || c == "\t" || c == "\n" || c == "\r" then
                    idx

                else
                    go (idx + 1)

        endIdx =
            go 0
    in
    ( String.left endIdx trimmed
    , String.dropLeft endIdx trimmed
    )


parseAttrsAndSelf : String -> ( List ( String, String ), Bool )
parseAttrsAndSelf s0 =
    let
        s =
            String.trim s0

        selfClosing =
            s
                |> String.trimRight
                |> String.endsWith "/"
    in
    ( splitAttrs s, selfClosing )


splitAttrs : String -> List ( String, String )
splitAttrs s =
    s
        |> trimTagTail
        |> wordsPreserveQuoted
        |> List.filter (not << String.isEmpty)
        |> List.map parseAttrOne
        |> List.filter (\( k, _ ) -> k /= "")


trimTagTail : String -> String
trimTagTail s =
    let
        noSlash =
            s
                |> String.trim
                |> (\t ->
                        if String.endsWith "/" t then
                            String.dropRight 1 t

                        else
                            t
                   )
    in
    String.trim noSlash


wordsPreserveQuoted : String -> List String
wordsPreserveQuoted s =
    let
        len =
            String.length s

        step : Int -> String -> List String -> Bool -> String -> List String
        step i buf parts inQuotes quoteChar =
            if i >= len then
                List.reverse (emit buf parts)

            else
                let
                    ch =
                        String.slice i (i + 1) s
                in
                if inQuotes then
                    if ch == quoteChar then
                        step (i + 1) (buf ++ ch) parts False ""

                    else
                        step (i + 1) (buf ++ ch) parts True quoteChar

                else if ch == "\"" || ch == "'" then
                    step (i + 1) (buf ++ ch) parts True ch

                else if isWs ch then
                    step (i + 1) "" (emit buf parts) False ""

                else
                    step (i + 1) (buf ++ ch) parts False ""
    in
    step 0 "" [] False ""


emit : String -> List String -> List String
emit buf parts =
    let
        t =
            String.trim buf
    in
    if t == "" then
        parts

    else
        t :: parts


parseAttrOne : String -> ( String, String )
parseAttrOne piece =
    case breakOnFirst "=" piece of
        Nothing ->
            ( normalizeAttr piece, "" )

        Just ( k, vRaw ) ->
            ( normalizeAttr k, stripQuotes (String.trim vRaw) )


breakOnFirst : String -> String -> Maybe ( String, String )
breakOnFirst sep s =
    String.indexes sep s
        |> List.head
        |> Maybe.map
            (\i ->
                ( String.left i s
                , String.dropLeft (i + String.length sep) s
                )
            )


stripQuotes : String -> String
stripQuotes s =
    let
        t =
            String.trim s
    in
    if (String.startsWith "\"" t && String.endsWith "\"" t)
        || (String.startsWith "'" t && String.endsWith "'" t)
    then
        t
            |> String.dropLeft 1
            |> String.dropRight 1

    else
        t


findChar : Char -> String -> Maybe Int
findChar c s =
    s
        |> String.indexes (String.fromChar c)
        |> List.head


isWs : String -> Bool
isWs ch =
    ch == " " || ch == "\t" || ch == "\n" || ch == "\r"



dropContentTags : List String
dropContentTags =
    [ "script", "style", "iframe", "object", "embed", "svg", "math" ]


normalizeTag : String -> String
normalizeTag s =
    s
        |> String.toLower
        |> String.filter (\c -> Char.isAlphaNum c || c == '-')


normalizeAttr : String -> String
normalizeAttr s =
    s
        |> String.toLower
        |> String.filter (\c -> Char.isAlphaNum c || c == '-')


isEventAttr : String -> Bool
isEventAttr k =
    String.startsWith "on" k


clean :
    { a
        | tags : List String
        , attributes : List String
        , urlAttributes : List String
        , allowedSchemes : List String
    }
    -> List Token
    -> List Token
clean cfg toks =
    let
        step : Token -> ( List Token, Int ) -> ( List Token, Int )
        step token ( acc, dropDepth ) =
            case token of
                TText s ->
                    if dropDepth > 0 then
                        ( acc, dropDepth )

                    else
                        ( TText (encodeHtml s) :: acc, dropDepth )

                TStart name attrs selfClosing ->
                    if List.member name dropContentTags then
                        if selfClosing then
                            ( acc, dropDepth )

                        else
                            ( acc, dropDepth + 1 )

                    else if dropDepth > 0 then
                        ( acc, dropDepth )

                    else if List.member name cfg.tags then
                        let
                            pruned =
                                attrs
                                    |> List.filter (\( k, _ ) -> List.member k cfg.attributes)
                                    |> List.filter (\( k, _ ) -> not (isEventAttr k))
                                    |> List.filter (\( k, _ ) -> k /= "style")
                                    |> List.filter (\( k, v ) -> if List.member k cfg.urlAttributes then schemeOk cfg.allowedSchemes v else True)
                                    |> List.map (\( k, v ) -> ( k, encodeHtml (stripControl (decodeForAttributeValue v)) ))
                        in
                        ( TStart name pruned selfClosing :: acc, dropDepth )

                    else
                        ( acc, dropDepth )

                TEnd name ->
                    if dropDepth > 0 then
                        if List.member name dropContentTags then
                            ( acc, dropDepth - 1 )

                        else
                            ( acc, dropDepth )

                    else if List.member name cfg.tags then
                        ( TEnd name :: acc, dropDepth )

                    else
                        ( acc, dropDepth )

        ( revOut, _ ) =
            List.foldl step ( [], 0 ) toks
    in
    List.reverse revOut


schemeOk : List String -> String -> Bool
schemeOk allowed v =
    let
        s =
            v
                |> decodeForUrlCheck
                |> String.trim
                |> String.toLower

        allowedNormalized =
            List.map normalizeScheme allowed
    in
    if s == "" then
        True

    else if String.startsWith "#" s then
        True

    else if String.startsWith "/" s then
        True

    else if String.startsWith "./" s || String.startsWith "../" s then
        True

    else
        case extractLeadingScheme s of
            Nothing ->
                True

            Just scheme ->
                List.member scheme allowedNormalized


normalizeScheme : String -> String
normalizeScheme scheme =
    let
        s =
            scheme
                |> String.toLower
                |> String.trim
    in
    if String.endsWith ":" s then
        s

    else
        s ++ ":"


extractLeadingScheme : String -> Maybe String
extractLeadingScheme url =
    let
        isSchemeChar c =
            Char.isAlphaNum c || c == '+' || c == '-' || c == '.'

        isIgnoredInScheme c =
            isControlOrWhitespace c || isZeroWidth c

        step consumed remaining =
            case remaining of
                [] ->
                    Nothing

                ':' :: _ ->
                    if List.isEmpty consumed then
                        Nothing

                    else
                        Just (String.fromList (List.reverse (':' :: consumed)))

                c :: rest ->
                    if isIgnoredInScheme c then
                        step consumed rest

                    else if List.isEmpty consumed then
                        if Char.isAlpha c then
                            step [ c ] rest

                        else
                            Nothing

                    else if isSchemeChar c then
                        step (c :: consumed) rest

                    else
                        Nothing
    in
    step [] (String.toList url)


render : List Token -> String
render toks =
    toks
        |> List.map render1
        |> String.join ""


render1 : Token -> String
render1 t =
    case t of
        TText s ->
            s

        TStart name attrs self ->
            let
                attrsStr =
                    attrs
                        |> List.map (\( k, v ) -> k ++ "=\"" ++ v ++ "\"")
                        |> String.join " "
            in
            if String.isEmpty attrsStr then
                if self then
                    "<" ++ name ++ " />"

                else
                    "<" ++ name ++ ">"

            else if self then
                "<" ++ name ++ " " ++ attrsStr ++ " />"

            else
                "<" ++ name ++ " " ++ attrsStr ++ ">"

        TEnd name ->
            "</" ++ name ++ ">"