module DetoXSS.Ast exposing
    ( Risk(..)
    , Warning
    , RiskNode(..)
    , classifyString
    , classifyExpression
    , classifyExpressionNode
    , scanExpression
    , scanExpressionNode
    , scanBalanced
    , scanBalancedVerbose
    , buildRiskTree
    , renderExpression
    , renderExpressionNode
    , renderRiskTree
    , fromStringToNode
    , classifyBalanced
    )

{-| Static XSS-oriented analysis for HTML-like strings.

This module provides the main detection layer of the package. It classifies
input as `Safe`, `Suspicious`, or `Dangerous`, and can also return warnings
explaining why a value was considered risky.

The analyzer is intended for detection and decision making. It does not rewrite
or sanitize the input by itself. For output sanitization, use
`DetoXSS.Sanitize`.

@docs Risk, Warning, RiskNode

@docs classifyString, classifyBalanced, classifyExpression, classifyExpressionNode

@docs scanBalanced, scanExpression, scanExpressionNode

@docs buildRiskTree, renderRiskTree

@docs renderExpression, renderExpressionNode

@docs fromStringToNode

-}

import Char
import DetoXSS.ExprParser as ExprParser exposing (HtmlAttribute, HtmlNode(..))
import String


type Risk
    = Safe
    | Suspicious
    | Dangerous


type alias Warning =
    { range : Maybe ExprParser.Position
    , risk : Risk
    , message : String
    }


type RiskNode
    = RiskNode
        { node : HtmlNode
        , selfWarnings : List Warning
        , aggregateRisk : Risk
        , children : List RiskNode
        }


type alias ScoreItem =
    { points : Int
    , message : String
    , riskHint : Risk
    }


stripDoctype : String -> String
stripDoctype src =
    let
        trimmed = String.trimLeft src
        upper   = String.toUpper trimmed
    in
    if String.startsWith "<!DOCTYPE" upper then
        case List.head (String.indexes ">" trimmed) of
            Just idx -> String.dropLeft (idx + 1) trimmed
            Nothing  -> src
    else
        src


fromStringToNode : String -> Result String (List HtmlNode)
fromStringToNode src =
    let
        trimmed =
            String.trimLeft (stripDoctype src)

        patched =
            if looksLikeUnclosedStartTag trimmed then
                trimmed ++ ">"
            else
                trimmed
    in
    case ExprParser.parseExpression trimmed of
        ExprParser.Ok nodes ->
            Ok nodes

        ExprParser.Err originalMsg ->
            if patched /= trimmed then
                case ExprParser.parseExpression patched of
                    ExprParser.Ok nodes ->
                        Ok nodes

                    ExprParser.Err _ ->
                        Err originalMsg
            else
                Err originalMsg


looksLikeUnclosedStartTag : String -> Bool
looksLikeUnclosedStartTag s =
    let
        lower =
            String.toLower (preDecodeForStringCheck s)
    in
    String.startsWith "<" (String.trimLeft lower)
        && not (String.contains ">" lower)
        && (
            containsAny lower
                [ " on"
                , "\ton"
                , "\non"
                , "src="
                , "href="
                , "style="
                , "id="
                , "class="
                ]
            || containsInlineEventAssignment lower
        )

classifyString : String -> Risk
classifyString src =
    src
        |> scanBalancedVerbose
        |> aggregateRisk


looksLikeSecurityRelevantParseFailure : String -> Bool
looksLikeSecurityRelevantParseFailure src =
    let
        raw =
            String.toLower src

        decodedRaw =
            String.toLower (preDecodeForStringCheck src)

        lower =
            normalize decodedRaw

        hasMarkupBoundary =
            String.contains "<" decodedRaw
                || String.contains "%3c" raw
                || String.contains "&#x3c" raw
                || String.contains "&#60" raw
    in
    hasMarkupBoundary
        && (
            containsAny raw
                [ " on"
                , "\ton"
                , "\non"
                , "src="
                , "href="
                , "style="
                , "srcdoc="
                , "</"
                , "<!"
                , "<?"
                , "%3c"
                , "&#x3c"
                , "&#60"
                ]
            || containsAny lower
                [ "script"
                , "iframe"
                , "object"
                , "embed"
                , "svg"
                , "math"
                , "xml"
                , "import"
                , "javascript"
                , "vbscript"
                , "datatexthtml"
                , "documentwrite"
                , "xmlhttprequest"
                , "innerhtml"
                , "onerror"
                , "onload"
                , "onclick"
                , "onfocus"
                , "onmouseover"
                ]
        )

scanBalanced : String -> List Warning
scanBalanced src =
    src
        |> scanBalancedVerbose
        |> compactWarnings


scanBalancedVerbose : String -> List Warning
scanBalancedVerbose src =
    let
        decoded =
            preDecodeForStringCheck src

        stringBasedWarnings =
            if decoded == src then
                stringWarnings src
            else
                stringWarnings src ++ stringWarnings decoded

        parsedBasedWarnings =
            case fromStringToNode src of
                Ok nodes ->
                    scanExpression nodes

                Err _ ->
                    if looksLikeAnalyzerShouldNotBeSilent src then
                        [ warn Nothing Suspicious "Malformed payload-like input could not be parsed fully" ]
                    else
                        []

        baseWarnings =
            dedupeWarningsByMessage (stringBasedWarnings ++ parsedBasedWarnings)

        fallbackWarnings =
            if List.isEmpty baseWarnings && looksLikeAnalyzerShouldNotBeSilent src then
                [ warn Nothing Suspicious "Payload-like input produced no analyzer findings" ]
            else
                []
    in
    dedupeWarningsByMessage (baseWarnings ++ fallbackWarnings)

looksLikeAnalyzerShouldNotBeSilent : String -> Bool
looksLikeAnalyzerShouldNotBeSilent src =
    let
        raw =
            String.toLower src

        decodedRaw =
            src
                |> preDecodeForStringCheck
                |> String.toLower

        compact =
            normalize decodedRaw

        hasMarkupBoundary =
            String.contains "<" decodedRaw
                || String.contains "%3c" raw
                || String.contains "&#60" raw
                || String.contains "&#x3c" raw

        hasExecutableCall =
            containsAny decodedRaw
                [ "alert("
                , "alert`"
                , "prompt("
                , "prompt`"
                , "confirm("
                , "confirm`"
                , "eval("
                , "eval`"
                , "settimeout("
                , "setinterval("
                , "fetch("
                , "xmlhttprequest"
                , "document.write"
                , "document.cookie"
                , "document.domain"
                , "window.location"
                , "innerhtml"
                , "outerhtml"
                ]

        hasInlineEvent =
            containsInlineEventAssignment decodedRaw

        hasRiskyTag =
            containsAny compact
                [ "script"
                , "iframe"
                , "object"
                , "embed"
                , "applet"
                , "svg"
                , "math"
                , "xml"
                , "xsl"
                , "stylesheet"
                , "foreignobject"
                , "animate"
                , "set"
                ]

        hasScriptableUrl =
            containsAny compact
                [ "javascript"
                , "vbscript"
                , "datatexthtml"
                , "datatextxml"
                ]

        hasCssVector =
            containsAny decodedRaw
                [ "expression("
                , "url("
                , "behavior:"
                , "@import"
                , "moz-binding"
                , "-o-link"
                ]
                || containsAny compact
                    [ "expression"
                    , "behavior"
                    , "mozbinding"
                    , "olink"
                    ]

        hasLegacyVector =
            containsAny decodedRaw
                [ ".htc"
                , "text/x-scriptlet"
                , "#default#"
                , "activexobject"
                , "htmlfile"
                , "allowscriptaccess"
                , "xmlns:"
                , "xlink:href"
                , "<![cdata["
                , "<?xml"
                ]

        hasContextBreak =
            containsAny decodedRaw
                [ "</script"
                , "</style"
                , "</xmp"
                , "</textarea"
                , "<!"
                , "<?"
                , "]]>"
                , "-->"
                , "/*"
                , "*/"
                ]
    in
    hasExecutableCall
        || (hasMarkupBoundary && hasInlineEvent)
        || (hasMarkupBoundary && hasScriptableUrl)
        || (hasMarkupBoundary && hasCssVector)
        || (hasMarkupBoundary && hasLegacyVector)
        || (hasMarkupBoundary && hasRiskyTag && hasContextBreak)
        || (hasMarkupBoundary && hasRiskyTag && hasExecutableCall)

classifyBalanced : String -> Risk
classifyBalanced src =
    src |> scanBalancedVerbose |> aggregateRisk


preDecodeForStringCheck : String -> String
preDecodeForStringCheck src =
    decodeRepeated 3 src


decodeRepeated : Int -> String -> String
decodeRepeated n src =
    if n <= 0 then
        src

    else
        let
            next =
                decodeOnceForStringCheck src
        in
        if next == src then
            src
        else
            decodeRepeated (n - 1) next


decodeOnceForStringCheck : String -> String
decodeOnceForStringCheck src =
    src
        |> stripNullBytes
        |> decodeHtmlNamedEntities
        |> decodeNumericEntitiesSimple
        |> decodeUnicodeEscapesStr
        |> decodeHexEscapesStr
        |> decodeJsOctalEscapesStr
        |> decodeCssEscapesStr
        |> decodeUrlEncodedStr



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


decodeHtmlNamedEntities : String -> String
decodeHtmlNamedEntities src =
    src
        |> String.replace "&lt;"      "<"
        |> String.replace "&gt;"      ">"
        |> String.replace "&amp;"     "&"
        |> String.replace "&quot;"    "\""
        |> String.replace "&#39;"     "'"
        |> String.replace "&#47;"     "/"
        |> String.replace "&sol;"     "/"
        |> String.replace "&num;"     "#"
        |> String.replace "&colon;"   ":"
        |> String.replace "&lpar;"    "("
        |> String.replace "&rpar;"    ")"
        |> String.replace "&equals;"  "="
        |> String.replace "&comma;"   ","
        |> String.replace "&period;"  "."
        |> String.replace "&semi;"    ";"
        |> String.replace "&apos;"    "'"
        |> String.replace "&NewLine;" "\n"
        |> String.replace "&Tab;"     "\t"


decodeNumericEntitiesSimple : String -> String
decodeNumericEntitiesSimple src =
    decodeNumHelp (String.toList src) []


decodeNumHelp : List Char -> List Char -> String
decodeNumHelp remaining acc =
    case remaining of
        [] ->
            String.fromList (List.reverse acc)

        '&' :: '#' :: 'x' :: rest ->
            let ( hexChars, after ) = collectAlphaNum rest [] in
            case after of
                ';' :: afterSemi ->
                    case hexToIntStr (String.fromList hexChars) of
                        Just code -> decodeNumHelp afterSemi (Char.fromCode code :: acc)
                        Nothing   -> decodeNumHelp rest (List.reverse (String.toList "&#x") ++ acc)
                _ ->
                    if not (List.isEmpty hexChars) then
                        case hexToIntStr (String.fromList hexChars) of
                            Just code -> decodeNumHelp after (Char.fromCode code :: acc)
                            Nothing   -> decodeNumHelp rest (List.reverse (String.toList "&#x") ++ acc)
                    else
                        decodeNumHelp rest (List.reverse (String.toList "&#x") ++ acc)

        '&' :: '#' :: rest ->
            let ( decChars, after ) = collectAlphaNum rest [] in
            case after of
                ';' :: afterSemi ->
                    case String.toInt (String.fromList decChars) of
                        Just code -> decodeNumHelp afterSemi (Char.fromCode code :: acc)
                        Nothing   -> decodeNumHelp rest (List.reverse (String.toList "&#") ++ acc)
                _ ->
                    if not (List.isEmpty decChars) then
                        case String.toInt (String.fromList decChars) of
                            Just code -> decodeNumHelp after (Char.fromCode code :: acc)
                            Nothing   -> decodeNumHelp rest (List.reverse (String.toList "&#") ++ acc)
                    else
                        decodeNumHelp rest (List.reverse (String.toList "&#") ++ acc)

        c :: rest ->
            decodeNumHelp rest (c :: acc)

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


isHexChar : Char -> Bool
isHexChar c =
    (c >= '0' && c <= '9')
        || (c >= 'a' && c <= 'f')
        || (c >= 'A' && c <= 'F')


isCssEscapeWhitespace : Char -> Bool
isCssEscapeWhitespace c =
    c == ' '
        || c == '\t'
        || c == '\n'
        || c == '\r'
        || c == '\u{000C}'

collectAlphaNum : List Char -> List Char -> ( List Char, List Char )
collectAlphaNum remaining acc =
    case remaining of
        [] -> ( List.reverse acc, [] )
        c :: rest ->
            if Char.isAlphaNum c then collectAlphaNum rest (c :: acc)
            else ( List.reverse acc, c :: rest )


hexToIntStr : String -> Maybe Int
hexToIntStr s =
    String.toList (String.toLower s)
        |> List.foldr
            (\c mAcc ->
                case mAcc of
                    Nothing -> Nothing
                    Just ( result, mult ) ->
                        case hexCharToIntLocal c of
                            Just d  -> Just ( result + d * mult, mult * 16 )
                            Nothing -> Nothing
            )
            (Just ( 0, 1 ))
        |> Maybe.map Tuple.first


hexCharToIntLocal : Char -> Maybe Int
hexCharToIntLocal c =
    if c >= '0' && c <= '9' then Just (Char.toCode c - Char.toCode '0')
    else if c >= 'a' && c <= 'f' then Just (Char.toCode c - Char.toCode 'a' + 10)
    else Nothing


decodeUnicodeEscapesStr : String -> String
decodeUnicodeEscapesStr src =
    decodeUniHelp (String.toList src) []


decodeUniHelp : List Char -> List Char -> String
decodeUniHelp remaining acc =
    case remaining of
        [] -> String.fromList (List.reverse acc)
        '\\' :: 'u' :: h1 :: h2 :: h3 :: h4 :: rest ->
            case hexToIntStr (String.fromList [ h1, h2, h3, h4 ]) of
                Just code -> decodeUniHelp rest (Char.fromCode code :: acc)
                Nothing   -> decodeUniHelp (h1 :: h2 :: h3 :: h4 :: rest) ('u' :: '\\' :: acc)
        c :: rest -> decodeUniHelp rest (c :: acc)


decodeHexEscapesStr : String -> String
decodeHexEscapesStr src =
    decodeHxHelp (String.toList src) []


decodeHxHelp : List Char -> List Char -> String
decodeHxHelp remaining acc =
    case remaining of
        [] -> String.fromList (List.reverse acc)
        '\\' :: 'x' :: h1 :: h2 :: rest ->
            case hexToIntStr (String.fromList [ h1, h2 ]) of
                Just code -> decodeHxHelp rest (Char.fromCode code :: acc)
                Nothing   -> decodeHxHelp (h1 :: h2 :: rest) ('x' :: '\\' :: acc)
        c :: rest -> decodeHxHelp rest (c :: acc)


decodeUrlEncodedStr : String -> String
decodeUrlEncodedStr src =
    decodeUrlHelp2 (String.toList src) []


decodeUrlHelp2 : List Char -> List Char -> String
decodeUrlHelp2 remaining acc =
    case remaining of
        [] -> String.fromList (List.reverse acc)
        '%' :: h1 :: h2 :: rest ->
            case hexToIntStr (String.fromList [ h1, h2 ]) of
                Just code ->
                    if
                        (code >= 0x20 && code <= 0x7E)
                            || code == 0x09
                            || code == 0x0A
                            || code == 0x0B
                            || code == 0x0C
                            || code == 0x0D
                    then
                        decodeUrlHelp2 rest (Char.fromCode code :: acc)
                    else
                        decodeUrlHelp2 (h1 :: h2 :: rest) ('%' :: acc)
                Nothing ->
                    decodeUrlHelp2 (h1 :: h2 :: rest) ('%' :: acc)
        c :: rest -> decodeUrlHelp2 rest (c :: acc)


classifyExpression : List HtmlNode -> Risk
classifyExpression nodes =
    nodes |> List.map buildRiskTree |> List.concatMap collectWarnings |> aggregateRisk


classifyExpressionNode : List HtmlNode -> Risk
classifyExpressionNode = classifyExpression


scanExpression : List HtmlNode -> List Warning
scanExpression nodes =
    nodes |> List.map buildRiskTree |> List.concatMap collectWarnings


scanExpressionNode : List HtmlNode -> List Warning
scanExpressionNode = scanExpression


buildRiskTree : HtmlNode -> RiskNode
buildRiskTree node =
    case node of
        Element elem ->
            let
                selfWarnings = scanElement elem
                childTrees   = List.map buildRiskTree elem.children
                agg          = aggregateRisk (selfWarnings ++ List.concatMap collectWarnings childTrees)
            in
            RiskNode { node = node, selfWarnings = selfWarnings, aggregateRisk = agg, children = childTrees }

        Text txt ->
            let sw = scanText txt.content (Just txt.position) in
            RiskNode { node = node, selfWarnings = sw, aggregateRisk = aggregateRisk sw, children = [] }

        Comment cmt ->
            let sw = scanText cmt.content (Just cmt.position) in
            RiskNode { node = node, selfWarnings = sw, aggregateRisk = aggregateRisk sw, children = [] }


nodeText : HtmlNode -> String
nodeText node =
    case node of
        Element elem ->
            elem.children
                |> List.map nodeText
                |> String.join " "

        Text txt ->
            txt.content

        Comment cmt ->
            cmt.content


collectWarnings : RiskNode -> List Warning
collectWarnings (RiskNode rn) =
    rn.selfWarnings ++ List.concatMap collectWarnings rn.children


aggregateRisk : List Warning -> Risk
aggregateRisk warnings =
    if List.any (\w -> w.risk == Dangerous) warnings then Dangerous
    else if List.any (\w -> w.risk == Suspicious) warnings then Suspicious
    else Safe


maxRisk : Risk -> Risk -> Risk
maxRisk a b =
    case ( a, b ) of
        ( Dangerous, _ ) -> Dangerous
        ( _, Dangerous ) -> Dangerous
        ( Suspicious, _ ) -> Suspicious
        ( _, Suspicious ) -> Suspicious
        _ -> Safe


dedupeWarningsByMessage : List Warning -> List Warning
dedupeWarningsByMessage warnings =
    warnings
        |> List.foldl
            (\warning acc ->
                if List.any (\w -> w.message == warning.message) acc then
                    acc
                else
                    warning :: acc
            )
            []
        |> List.reverse



compactWarnings : List Warning -> List Warning
compactWarnings warnings =
    let
        deduped =
            dedupeWarningsByMessage warnings

        context =
            { hasSpecificUrl = hasSpecificUrlWarning deduped
            , hasSpecificEvent = hasSpecificEventWarning deduped
            , hasSpecificScriptTag = hasSpecificScriptTagWarning deduped
            , hasSpecificStyle = hasSpecificStyleWarning deduped
            , hasSpecificSink = hasSpecificSinkWarning deduped
            }

        filtered =
            deduped
                |> List.filter (not << isRedundantWarning context)
    in
    if List.isEmpty filtered && not (List.isEmpty deduped) then
        keepHighestRiskWarnings deduped

    else
        filtered


keepHighestRiskWarnings : List Warning -> List Warning
keepHighestRiskWarnings warnings =
    let
        highest =
            aggregateRisk warnings
    in
    warnings
        |> List.filter (\w -> w.risk == highest)
        |> List.take 1


hasSpecificUrlWarning : List Warning -> Bool
hasSpecificUrlWarning warnings =
    List.any
        (\w ->
            String.startsWith "Scriptable URL scheme in " w.message
                || String.startsWith "HTML/script-bearing data payload in " w.message
                || String.startsWith "Encoded/obfuscated scriptable payload in " w.message
        )
        warnings


hasSpecificEventWarning : List Warning -> Bool
hasSpecificEventWarning warnings =
    List.any
        (\w ->
            String.startsWith "Inline event handler " w.message
                || w.message == "Legacy script event binding attribute"
                || w.message == "srcdoc can embed executable HTML"
        )
        warnings


hasSpecificScriptTagWarning : List Warning -> Bool
hasSpecificScriptTagWarning warnings =
    List.any
        (\w ->
            String.startsWith "Dangerous tag <" w.message
                || w.message == "Script tag is executable"
                || String.startsWith "Script element" w.message
        )
        warnings


hasSpecificStyleWarning : List Warning -> Bool
hasSpecificStyleWarning warnings =
    List.any (\w -> w.message == "Style attribute contains execution-adjacent content") warnings


hasSpecificSinkWarning : List Warning -> Bool
hasSpecificSinkWarning warnings =
    List.any
        (\w ->
            w.message == "srcdoc can embed executable HTML"
                || w.message == "Executable HTML sink assignment"
        )
        warnings


isRedundantWarning :
    { hasSpecificUrl : Bool
    , hasSpecificEvent : Bool
    , hasSpecificScriptTag : Bool
    , hasSpecificStyle : Bool
    , hasSpecificSink : Bool
    }
    -> Warning
    -> Bool
isRedundantWarning context warning =
    let
        msg =
            warning.message
    in
    (context.hasSpecificUrl && isGenericUrlWarning msg)
        || (context.hasSpecificEvent && isGenericEventWarning msg)
        || (context.hasSpecificScriptTag && isGenericScriptTagWarning msg)
        || (context.hasSpecificStyle && isGenericStyleWarning msg)
        || (context.hasSpecificSink && isGenericSinkWarning msg)


isGenericUrlWarning : String -> Bool
isGenericUrlWarning msg =
    List.member msg
        [ "Text contains scriptable URL scheme"
        , "Text combines URL context with executable payload"
        , "Scriptable URL scheme"
        , "URL context with executable payload"
        , "Fragmented executable payload"
        , "Fragmented executable payload pattern"
        , "JavaScript function call pattern"
        ]
        || String.startsWith "Executable marker in URL-like attribute " msg


isGenericEventWarning : String -> Bool
isGenericEventWarning msg =
    List.member msg
        [ "Element with event handler"
        , "HTML tag with inline event handler"
        , "Inline event handler assignment"
        , "Generic inline event handler detected"
        , "Generic inline event handler assignment"
        , "Text combines HTML carrier and event marker"
        , "Text combines media context and executable marker"
        , "Media context with executable marker"
        , "Fragmented executable payload"
        , "Fragmented executable payload pattern"
        , "JavaScript function call pattern"
        ]


isGenericScriptTagWarning : String -> Bool
isGenericScriptTagWarning msg =
    List.member msg
        [ "Text contains executable tag pattern"
        , "Obfuscated/broken script tag"
        , "External script src reference"
        , "JavaScript function call pattern"
        ]


isGenericStyleWarning : String -> Bool
isGenericStyleWarning msg =
    List.member msg
        [ "CSS-based execution vector"
        , "Text combines HTML carrier and event marker"
        ]


isGenericSinkWarning : String -> Bool
isGenericSinkWarning msg =
    List.member msg
        [ "Executable HTML sink assignment"
        , "JavaScript sink-like API marker"
        ]


warn : Maybe ExprParser.Position -> Risk -> String -> Warning
warn pos risk msg =
    { range = pos, risk = risk, message = msg }


score : Int -> Risk -> String -> ScoreItem
score points riskHint message =
    { points = points, riskHint = riskHint, message = message }


itemsToWarnings : Maybe ExprParser.Position -> String -> List ScoreItem -> List Warning
itemsToWarnings pos _ items =
    items
        |> List.filter (\i -> i.points > 0)
        |> List.map (\i -> warn pos i.riskHint i.message)



scanElement :
    { tag : String
    , attributes : List HtmlAttribute
    , children : List HtmlNode
    , position : ExprParser.Position
    }
    -> List Warning
scanElement elem =
    let
        tagLower     = String.toLower elem.tag
        tagItems     = scoreTag tagLower
        attrWarnings = List.concatMap (scanAttribute tagLower) elem.attributes
        structItems  = scoreStructure tagLower elem.attributes elem.children
    in
    itemsToWarnings (Just elem.position) ("<" ++ tagLower ++ ">") tagItems
        ++ attrWarnings
        ++ itemsToWarnings (Just elem.position) ("<" ++ tagLower ++ "> structure") structItems


scoreTag : String -> List ScoreItem
scoreTag tag =
    if List.member tag [ "iframe", "object", "embed", "applet" ] then
        [ score 4 Dangerous ("Dangerous tag <" ++ tag ++ ">") ]

    else if tag == "script" then
        [ score 4 Dangerous "Script tag is executable" ]

    else if List.member tag [ "svg", "math", "style", "base" ] then
        [ score 1 Suspicious ("Potentially risky tag <" ++ tag ++ ">") ]

    else if List.member tag [ "form", "meta" ] then
        [ score 1 Suspicious ("Potentially risky tag <" ++ tag ++ ">") ]

    else if List.member tag [ "animate", "set", "use", "feimage", "filter", "foreignobject", "handler", "listener", "image" ] then
        [ score 2 Suspicious ("SVG/XML namespace element <" ++ tag ++ ">") ]

    else
        []


scanAttribute : String -> HtmlAttribute -> List Warning
scanAttribute tagLower attr =
    let
        nameLower        = String.toLower attr.name
        rawValue         = attr.value
        decodedValue     = preDecodeForStringCheck rawValue
        valueLower       = normalize rawValue
        decodedValueLow  = normalize decodedValue
        pos              = Just attr.position
        items            = scoreAttribute tagLower nameLower valueLower rawValue
        decodedItems     = scoreAttribute tagLower nameLower decodedValueLow decodedValue
    in
    itemsToWarnings pos (attributeContext tagLower nameLower rawValue) (dedupeScoreItems (items ++ decodedItems))


scoreAttribute : String -> String -> String -> String -> List ScoreItem
scoreAttribute tagName name valueLower rawValue =
    let combined = tagName ++ " " ++ name ++ " " ++ valueLower in
    dedupeScoreItems <|
        List.concat
            [ scoreEventAttribute name valueLower
            , scoreUrlAttribute name valueLower rawValue
            , scoreSpecialAttribute name valueLower rawValue
            , scoreBrokenPayload combined
            ]


scoreEventAttribute : String -> String -> List ScoreItem
scoreEventAttribute name valueLower =
    if String.startsWith "on" name then
        [ score 4 Dangerous ("Inline event handler " ++ name) ]
    else if name == "srcdoc" then
        [ score 4 Dangerous "srcdoc can embed executable HTML" ]
    else if String.startsWith "data-" name && containsAny valueLower executableWords then
        [ score 1 Suspicious "data- attribute carries executable marker" ]
    else
        []


scoreUrlAttribute : String -> String -> String -> List ScoreItem
scoreUrlAttribute name valueLower rawValue =
    if isUrlLikeAttribute name then
        List.concat
            [ if containsAny valueLower [ "javascript", "vbscript", "mocha", "livescript" ] then
                [ score 4 Dangerous ("Scriptable URL scheme in " ++ name) ]
              else []
            , if isDataHtmlPayload valueLower then
                [ score 4 Dangerous ("HTML/script-bearing data payload in " ++ name) ]
              else []
            , if containsAny valueLower encodedScriptSignals then
                [ score 2 Suspicious ("Encoded/obfuscated scriptable payload in " ++ name) ]
              else []
            , if containsAny valueLower [ "alert", "prompt", "confirm", "windowonerror", "documentcookie", "documentwrite", "xmlhttprequest" ] then
                [ score 2 Suspicious ("Executable marker in URL-like attribute " ++ name) ]
              else []
            ]
    else []


scoreSpecialAttribute : String -> String -> String -> List ScoreItem
scoreSpecialAttribute name valueLower rawValue =
    let
        rawLower =
            rawValue
                |> preDecodeForStringCheck
                |> String.toLower

        compact =
            normalize rawLower
    in
    List.concat
        [ if name == "style"
                && (
                    containsAny rawLower
                        [ "expression("
                        , "url("
                        , "behavior:"
                        , "@import"
                        , "javascript:"
                        , "vbscript:"
                        , "moz-binding"
                        , "-o-link"
                        ]
                    || containsAny compact
                        [ "expression"
                        , "url"
                        , "behavior"
                        , "import"
                        , "javascript"
                        , "vbscript"
                        , "mozbinding"
                        , "olink"
                        ]
                )
          then
            [ score 2 Suspicious "Style attribute contains execution-adjacent content" ]

          else
            []
        , if name == "event" && containsAny valueLower [ "onreadystatechange", "onload", "onclick", "onerror" ] then
            [ score 3 Dangerous "Legacy script event binding attribute" ]
          else
            []
        , if name == "for" && containsAny valueLower [ "document", "window" ] then
            [ score 2 Suspicious "Legacy script target binding attribute" ]
          else
            []
        ]


scoreBrokenPayload : String -> List ScoreItem
scoreBrokenPayload combined =
    List.concat
        [ if containsAny combined
                [ "javascriptalert", "onerroralert", "onloadalert", "onclickalert"
                , "srconerror", "srcjavascript", "hrefjavascript", "windowonerroralert"
                ]
          then [ score 2 Suspicious "Fragmented executable payload pattern" ]
          else []
        , if containsAny combined mediaWords
                && containsAny combined [ "onerror", "onload", "alert", "eval", "windowonerror" ]
          then [ score 2 Suspicious "Media context with executable marker" ]
          else []
        , if containsAny combined [ "href", "src", "action", "formaction" ]
                && containsAny combined [ "javascript", "vbscript", "datatexthtml", "base64" ]
          then [ score 3 Dangerous "URL context with executable payload" ]
          else []
        ]


scoreStructure : String -> List HtmlAttribute -> List HtmlNode -> List ScoreItem
scoreStructure tag attrs children =
    let
        attrNames    = attrs |> List.map (.name >> String.toLower)
        attrValues   = attrs |> List.map (.value >> normalize)
        hasEventAttr = List.any (\n -> String.startsWith "on" n) attrNames
        combinedVals = String.join " " attrValues
        hasSrc       = List.any (\n -> n == "src") attrNames

        childRaw =
            children
                |> List.map nodeText
                |> String.join " "
                |> preDecodeForStringCheck
                |> String.toLower

        childNorm =
            normalize childRaw

        hasInlineCode =
            containsAny (combinedVals ++ " " ++ childNorm)
                [ "alert", "eval", "prompt", "confirm"
                , "settimeout", "setinterval", "fetch"
                , "xmlhttprequest", "documentwrite", "documentcookie"
                , "windowlocation", "innerhtml", "outerhtml"
                ]
                || containsAny childRaw
                    [ "alert(", "eval(", "prompt(", "confirm("
                    , "settimeout(", "setinterval(", "fetch("
                    , "document.write(", "document.cookie", "window.location"
                    , "innerhtml", "outerhtml"
                    ]
    in
    List.concat
        [
          if tag == "script" && hasInlineCode then
            [ score 4 Dangerous "Script element with inline executable content" ]
          else if tag == "script" && hasSrc && not hasInlineCode then
            [ score 4 Dangerous "Script element with external src" ]
          else []

        , if hasEventAttr then
            [ score 4 Dangerous "Element with event handler" ]
          else []

        , if containsAny combinedVals
                [ "documentcookie", "documenturl", "windowlocation"
                , "innerhtml", "outerhtml"
                ]
          then [ score 2 Suspicious "Attribute references sensitive JS sink" ]
          else []

        , if List.member "tabindex" attrNames
                && hasEventAttr
                && not (List.member tag [ "a", "button", "input", "select", "textarea" ])
          then [ score 1 Suspicious "Non-interactive element with tabindex and event" ]
          else []
        ]


scanText : String -> Maybe ExprParser.Position -> List Warning
scanText content pos =
    let
        rawLower        = String.toLower content
        decodedRawLower = String.toLower (preDecodeForStringCheck content)
        lower           = normalize content
        decoded         = normalize (preDecodeForStringCheck content)
        items           = scoreText lower ++ scoreText decoded ++ scoreRaw rawLower ++ scoreRaw decodedRawLower
    in
    itemsToWarnings pos "text node" (dedupeScoreItems items)


stringWarnings : String -> List Warning
stringWarnings src =
    let
        rawLower        = String.toLower src
        decodedRawLower = String.toLower (preDecodeForStringCheck src)
        lower           = normalize src
        decoded         = normalize (preDecodeForStringCheck src)
        items           = scoreText lower ++ scoreText decoded ++ scoreRaw rawLower ++ scoreRaw decodedRawLower
    in
    itemsToWarnings Nothing "string" (dedupeScoreItems items)

normalizeJsGlue : String -> String
normalizeJsGlue src =
    src
        |> String.toLower
        |> String.replace "\"" ""
        |> String.replace "'" ""
        |> String.replace "`" ""
        |> String.replace "“" ""
        |> String.replace "”" ""
        |> String.replace "‘" ""
        |> String.replace "’" ""
        |> String.replace "+" ""
        |> String.replace "[" ""
        |> String.replace "]" ""
        |> String.replace " " ""
        |> String.replace "\t" ""
        |> String.replace "\n" ""
        |> String.replace "\r" ""

looksLikeBrokenScriptTag : String -> Bool
looksLikeBrokenScriptTag raw =
    let
        compact =
            raw
                |> String.toLower
                |> String.replace "\\0" ""
                |> String.replace "\u{0000}" ""
                |> String.replace "+" ""
                |> String.replace "/" ""
                |> String.replace "\\" ""
                |> String.replace " " ""
                |> String.replace "\t" ""
                |> String.replace "\n" ""
                |> String.replace "\r" ""
    in
    String.contains "<script" compact
        || String.contains "</script" compact
        || String.contains "scriptfor" compact

scoreRaw : String -> List ScoreItem
scoreRaw raw =
    let
        glued =
            normalizeJsGlue raw
    in
    dedupeScoreItems <|
        List.concat
            [ if containsAny raw [ "alert(", "prompt(", "confirm(", "eval(" ] then
                [ score 3 Dangerous "JavaScript function call pattern" ]
              else []
            , if containsAny glued
                    [ "topalert("
                    , "windowalert("
                    , "selfalert("
                    , "parentalert("
                    , "thisalert("
                    , "topconfirm("
                    , "windowconfirm("
                    , "selfconfirm("
                    , "parentconfirm("
                    , "thisconfirm("
                    , "topprompt("
                    , "windowprompt("
                    , "selfprompt("
                    , "parentprompt("
                    , "thisprompt("
                    , "topeval("
                    , "windoweval("
                    ]
              then
                [ score 3 Dangerous "Obfuscated JS property call" ]
              else []
            , if looksLikeBrokenScriptTag raw then
                [ score 3 Dangerous "Obfuscated/broken script tag" ]
              else []
            , if String.contains "&#00" raw then
                [ score 3 Dangerous "Padded numeric entity obfuscation" ]
              else []
            , if countEntityOccurrences raw >= 6 then
                [ score 3 Dangerous "Dense numeric entity obfuscation" ]
              else []
            , if containsAny raw [ "alert`", "prompt`", "confirm`", "eval`" ] then
                [ score 3 Dangerous "Template literal JS call" ]
              else []
            , if containsAny raw [ ")(", ")(1)", ")(0)" ]
                && containsAny raw [ "alert", "prompt", "confirm" ]
            then
            [ score 3 Dangerous "IIFE-style function call pattern" ]
            else []
            , if containsAny raw [ "settimeout(", "setinterval(", "settimeout`", "setinterval`" ] then
                [ score 3 Dangerous "Timer-based execution call" ]
              else []
            , if containsAny raw [ "fetch(", "xmlhttprequest(", "fetch`" ] then
                [ score 3 Dangerous "Network exfiltration call" ]
              else []
            , if containsAny raw [ "javascript:", "vbscript:", "data:text/html", "data:text/xml" ] then
                [ score 4 Dangerous "Scriptable URL scheme" ]
              else []
            , if containsAny raw
                    [ "onerror=", "onload=", "onclick=", "onmouseover="
                    , "onfocus=", "onblur=", "onchange=", "oninput="
                    , "ondragend=", "ondragstart=", "ondrop=", "onpaste="
                    , "onkeydown=", "onkeyup=", "onkeypress="
                    , "onreadystatechange=", "onactivate=", "ondeactivate="
                    , "ontoggle=", "onpointerdown=", "onpointerup="
                    , "onbegin=", "onrepeat=", "onfinish="
                    , "onmouseleave=", "onmouseenter=", "onmouseout=", "onmouseup="
                    , "onmousedown=", "onmousemove=", "ondblclick=", "oncontextmenu="
                    , "onfocusin=", "onfocusout=", "onsubmit=", "onreset=", "onselect="
                    , "onscroll=", "onresize=", "onunload=", "onbeforeunload="
                    , "onhashchange=", "onpopstate=", "onmessage=", "onstorage="
                    , "onbeforecopy=", "onbeforecut=", "onbeforepaste="
                    , "onbeforedeactivate=", "onbeforeactivate="
                    , "ondragenter=", "ondragleave=", "ondragover="
                    , "onpointerenter=", "onpointerleave=", "onpointermove="
                    , "onpointerout=", "onpointercancel="
                    , "oncut=", "oncopy=", "onopen=", "onclose=", "onshow="
                    , "onpropertychange=", "onlosecapture=", "onseeked="
                    , "onprogress=", "onanimationstart=", "onanimationend="
                    , "onanimationiteration=", "ontransitionend="
                    , "onselectstart=", "onhelp="
                    , "onxxx=", "onsubmitin=", "onclickout=", "onxxxxxx="
                    ]
              then [ score 4 Dangerous "Inline event handler assignment" ]
              else []

            , if String.contains "<" raw
                    && containsAny raw
                        [ " ona=", " onb=", " onc=", " ond=", " one=", " onf="
                        , " ong=", " onh=", " oni=", " onj=", " onk=", " onl="
                        , " onm=", " onn=", " ono=", " onp=", " onq=", " onr="
                        , " ons=", " ont=", " onu=", " onv=", " onw=", " onx="
                        , " ony=", " onz="
                        , "\tona=", "\tonb=", "\tonc=", "\tond=", "\tone=", "\tonf="
                        , "\tong=", "\tonh=", "\toni=", "\tonj=", "\tonk=", "\tonl="
                        , "\tonm=", "\tonn=", "\tono=", "\tonp=", "\tonr=", "\tons="
                        , "\tont=", "\tonu=", "\tonv=", "\tonw=", "\tonx=", "\tony="
                        ]
              then [ score 4 Dangerous "Generic inline event handler detected" ]
              else []
            , if containsInlineEventAssignment raw then
                [ score 4 Dangerous "Generic inline event handler assignment" ]
              else []
            , if looksLikeContextBreak raw then
                [ score 2 Suspicious "Context-breaking injection probe" ]
              else []
            , if looksLikeCssExecution raw then
                [ score 2 Suspicious "CSS-based execution vector" ]
              else []
            , if looksLikeXmlNamespaceInjection raw then
                [ score 2 Suspicious "XML/SVG namespace-based injection" ]
              else []
            , if containsAny raw [ "srcdoc=", "innerhtml=", "outerhtml=" ] then
                [ score 3 Dangerous "Executable HTML sink assignment" ]
              else []
            ]


scoreText : String -> List ScoreItem
scoreText lower =
    dedupeScoreItems <|
        List.concat
            [ if containsAny lower [ "<script", "<iframe", "<object", "<embed" ] then
                [ score 4 Dangerous "Text contains executable tag pattern" ]
              else []

            , if containsAny lower [ "javascript", "vbscript", "mocha", "livescript" ] then
                [ score 3 Dangerous "Text contains scriptable URL scheme" ]
              else []

            , if isDataHtmlPayload lower then
                [ score 4 Dangerous "Text contains HTML/script-bearing data payload" ]
              else []

            , if containsAny lower htmlCarrierWords && containsAny lower eventWords then
                [ score 3 Dangerous "Text combines HTML carrier and event marker" ]
              else []

            , if containsAny lower mediaWords
                    && containsAny lower [ "onerror", "onload", "alert", "eval", "windowonerror" ]
              then [ score 3 Dangerous "Text combines media context and executable marker" ]
              else []

            , if containsAny lower [ "href", "src", "action", "formaction" ]
                    && containsAny lower [ "javascript", "vbscript", "datatexthtml", "base64" ]
              then [ score 3 Dangerous "Text combines URL context with executable payload" ]
              else []

            , if looksFragmentedExecutablePayload lower then
                [ score 2 Suspicious "Fragmented executable payload" ]
              else []

            , if containsAny lower
                    [ "documentcookie", "documenturl", "windowonerror"
                    , "documentqueryselector", "documentwrite", "innerhtml"
                    ]
              then [ score 2 Suspicious "JavaScript sink-like API marker" ]
              else []

            , if looksLikePureJsPayload lower then
                [ score 3 Dangerous "Pure JavaScript execution payload" ]
              else []

            , if looksLikeContextBreak lower then
                [ score 2 Suspicious "Context-breaking injection probe" ]
              else []

            , if looksLikeCssExecution lower then
                [ score 2 Suspicious "CSS-based execution vector" ]
              else []

            , if looksLikeXmlNamespaceInjection lower then
                [ score 2 Suspicious "XML/SVG namespace-based injection" ]
              else []

            , if looksLikeTagWithEvent lower then
                [ score 3 Dangerous "HTML tag with inline event handler" ]
              else []

            , if looksLikeExternalScriptSrc lower then
                [ score 2 Suspicious "External script src reference" ]
              else []

            , if looksLikeDenseEntityEncoding lower then
                [ score 3 Dangerous "Dense numeric/hex entity encoding (obfuscation)" ]
              else []
            ]


containsInlineEventAssignment : String -> Bool
containsInlineEventAssignment raw =
    scanInlineEventAssignment (String.toList (" " ++ String.toLower raw))


scanInlineEventAssignment : List Char -> Bool
scanInlineEventAssignment chars =
    case chars of
        [] ->
            False

        boundary :: 'o' :: 'n' :: rest ->
            if isEventBoundary boundary && eventNameHasEquals 0 rest then
                True
            else
                scanInlineEventAssignment ('o' :: 'n' :: rest)

        _ :: rest ->
            scanInlineEventAssignment rest

isSpaceChar : Char -> Bool
isSpaceChar c =
    c == ' '
        || c == '\t'
        || c == '\n'
        || c == '\r'
        || c == '\u{000B}' -- vertical tab
        || c == '\u{000C}' -- form feed

eventNameHasEquals : Int -> List Char -> Bool
eventNameHasEquals count chars =
    case chars of
        [] ->
            False

        '=' :: _ ->
            count >= 2

        c :: rest ->
            if isSpaceChar c && count >= 2 then
                skipSpacesThenEquals rest

            else if Char.isAlphaNum c || c == '-' || c == '_' || c == ':' then
                eventNameHasEquals (count + 1) rest

            else
                False


skipSpacesThenEquals : List Char -> Bool
skipSpacesThenEquals chars =
    case chars of
        [] ->
            False

        '=' :: _ ->
            True

        c :: rest ->
            if isSpaceChar c then
                skipSpacesThenEquals rest
            else
                False


isEventBoundary : Char -> Bool
isEventBoundary c =
    c == '<'
        || c == '/'
        || c == '>'
        || c == '"'
        || c == '\''
        || c == '`'
        || c == '='
        || isSpaceChar c


looksLikeTagWithEvent : String -> Bool
looksLikeTagWithEvent lower =
    let
        hasTag = String.contains "<" lower
        hasOnEvent =
            containsAny lower
                [ " ona=", " onb=", " onc=", " ond=", " one=", " onf="
                , " ong=", " onh=", " oni=", " onj=", " onk=", " onl="
                , " onm=", " onn=", " ono=", " onp=", " onr=", " ons="
                , " ont=", " onu=", " onv=", " onw=", " onx=", " ony="
                , "\tona=", "\tonb=", "\tonc=", "\tond=", "\tone=", "\tonf="
                , "\tonm=", "\tonn=", "\tons=", "\tont=", "\tonx="
                , "/ona=", "/onb=", "/onc=", "/ond=", "/one=", "/onf="
                , "/onm=", "/onn=", "/ons=", "/ont=", "/onx="
                , "1ona=", "1onb=", "1onc=", "1ond=", "1one=", "1onf="
                , "1ong=", "1onh=", "1oni=", "1onj=", "1onk=", "1onl="
                , "1onm=", "1onn=", "1ono=", "1onp=", "1onr=", "1ons="
                , "1ont=", "1onu=", "1onv=", "1onw=", "1onx=", "1ony="
                ]

        hasSafeExec =
            containsAny lower
                [ "xmlhttprequest"
                , "documentwrite"
                , "documentcookie"
                , "documentdomain"
                , "windowlocation"
                , "windowonerror"
                , "innerhtml"
                , "outerhtml"
                , "insertadjacenthtml"
                , "settimeout"
                , "setinterval"
                , "mathrandom"
                , "datenow"
                , "fetch"
                , "navigatorvibrate"
                , "locationhref"
                , "historypushstate"
                , "=alert", ";alert", "=prompt", "=confirm", ";confirm"
                , "=settimeout", "=fetch", "=xmlhttprequest"
                ]
    in
    hasTag && hasOnEvent && hasSafeExec

looksLikePureJsPayload : String -> Bool
looksLikePureJsPayload lower =
    let
        hasJsStructure =
            containsAny lower
                [ "topalert", "windowalert", "selfalert", "framealert"
                , "topconfirm", "windowconfirm", "topprompt", "windowprompt"
                , "setconstructor", "functionconstructor"
                , "aalert", "xalert", "nalert", "falert"
                , "aprompt", "xprompt", "aconfirm"
                , "alsource", "ertsource"
                , "navigatorvibrate", "locationassign", "locationreplace"
                , "locationhref", "locationreload"
                , "historypushstate", "historyreplacestate"
                , "findalert", "findprompt", "findconfirm"
                , "1findalert", "1findconfirm", "1findprompt"
                , "tostring30", "tostring36"
                ]

        hasSafeJs =
            containsAny lower
                [ "xmlhttprequest", "documentwrite", "documentcookie"
                , "windowlocation", "innerhtml", "outerhtml"
                , "insertadjacenthtml", "windowonerror", "documentdomain"
                ]
    in
    hasJsStructure || hasSafeJs


looksLikeContextBreak lower =
    containsAny lower
        [ "</svg>//"
        , "</form>//"
        , "</style>//"
        , "</a>//"
        , "</math>//"
        , "</html>//"
        , "</div>//"
        , "</script>//"
        , "</stylesheet>//"
        , "</root>//"
        , "]]></x"
        , "</scrip"
        , "*/<script"
        , "//[\"'"
        , "-->]]>"
        ]


looksLikeCssExecution : String -> Bool
looksLikeCssExecution lower =
    containsAny lower
        [ "expression("
        , "moz-binding"
        , "-o-link"
        , "behavior:"
        , "xss:expression"
        , "expressio\\00"
        , "@import"
        ]


looksLikeXmlNamespaceInjection : String -> Bool
looksLikeXmlNamespaceInjection lower =
    containsAny lower
        [ "xmlns:"
        , "ev:event"
        , "xlink:href"
        , "<?xml"
        , "<![cdata["
        , "xml-stylesheet"
        ]


looksLikeExternalScriptSrc : String -> Bool
looksLikeExternalScriptSrc lower =
    String.contains "<script" lower
        && String.contains "src" lower
        && not (containsAny lower
            [ "alert", "eval", "prompt", "confirm", "settimeout"
            , "setinterval", "fetch", "xmlhttprequest", "documentwrite"
            ])


looksLikeDenseEntityEncoding : String -> Bool
looksLikeDenseEntityEncoding lower =
    let
        countOccurrences sub str =
            case String.indexes sub str of
                [] -> 0
                xs -> List.length xs
    in
    countOccurrences "&#" lower >= 8


looksLikeObfuscatedPayload : String -> Bool
looksLikeObfuscatedPayload src =
    let
        lower    = normalize (preDecodeForStringCheck src)
        rawLower = String.toLower src
    in
    containsAny lower
        [ "alert", "prompt", "confirm", "eval", "settimeout", "setinterval"
        , "javascript", "vbscript", "onerror", "onload", "onclick", "onmouse"
        , "ondrag", "onfocus", "onblur", "onkey", "onchange", "onsubmit"
        , "onresize", "onscroll", "onanimation", "ontransition", "onactivate"
        , "ondeactivate", "onbeforeactivate", "onreadystatechange"
        , "documentcookie", "xmlhttprequest", "fetch", "script", "iframe"
        , "documentwrite", "documentdomain", "windowlocation", "innerhtml"
        , "mathrandom", "datenow", "documenttitle", "selfframes"
        ]
        || ( String.contains "<" rawLower
                && containsAny rawLower [ " on", "=on", "/on" ]
           )


looksFragmentedExecutablePayload : String -> Bool
looksFragmentedExecutablePayload lower =
    let
        hasCarrier =
            containsAny lower (mediaWords ++ htmlCarrierWords ++ [ "href", "src", "script", "iframe", "data" ])

        hasExec =
            containsAny lower (eventWords ++ executableWords)

        hasCollapsed =
            containsAny lower
                [ "javascriptalert", "onerroralert", "onloadalert", "onclickalert"
                , "srconerror", "srcjavascript", "hrefjavascript", "windowonerroralert"
                ]
    in
    hasCollapsed || (hasCarrier && hasExec)


isKnownTag : String -> Bool
isKnownTag tag =
    List.member tag
        [ "a", "abbr", "address", "area", "article", "aside", "audio"
        , "b", "base", "bdi", "bdo", "blockquote", "body", "br", "button"
        , "canvas", "caption", "cite", "code", "col", "colgroup", "data"
        , "datalist", "dd", "del", "details", "dfn", "dialog", "div", "dl", "dt"
        , "em", "embed", "fieldset", "figcaption", "figure", "footer", "form"
        , "h1", "h2", "h3", "h4", "h5", "h6", "head", "header", "hr", "html"
        , "i", "iframe", "img", "input", "ins"
        , "kbd", "label", "legend", "li", "link"
        , "main", "map", "mark", "menu", "meta", "meter"
        , "nav", "noscript", "object", "ol", "optgroup", "option", "output"
        , "p", "picture", "pre", "progress"
        , "q", "rp", "rt", "ruby"
        , "s", "samp", "script", "section", "select", "small", "source"
        , "span", "strong", "style", "sub", "summary", "sup"
        , "table", "tbody", "td", "template", "textarea", "tfoot", "th"
        , "thead", "time", "title", "tr", "track"
        , "u", "ul", "var", "video", "wbr"
        , "applet", "bgsound", "blink", "command", "frame", "frameset"
        , "isindex", "keygen", "layer", "listing", "marquee", "nextid"
        , "nobr", "noembed", "noframes", "plaintext", "rb", "rtc", "shadow"
        , "spacer", "strike", "tt", "xmp"
        ]


eventWords : List String
eventWords =
    [ "onerror", "onload", "onclick", "onmouseover", "onmouseenter", "onmouseleave"
    , "onpointer", "onfocus", "onfocusin", "onfocusout", "onblur", "onchange"
    , "oninput", "onanimation", "ontransition", "ondrag", "ondrop", "onpaste"
    , "oncopy", "oncut", "onkey", "onmouse", "onsubmit", "onreset", "onselect"
    , "onscroll", "onresize", "onunload", "onbeforeunload", "onhashchange"
    , "onpopstate", "onmessage", "onstorage"
    , "onactivate", "ondeactivate", "onbeforeactivate", "onbeforecopy"
    , "onbeforecut", "onbeforepaste", "onbeforedeactivate"
    , "oncontextmenu", "ondblclick", "ondragend", "ondragenter", "ondragleave"
    , "ondragover", "ondragstart", "onmousedown", "onmouseout", "onmouseup"
    , "onmousemove", "onpointerdown", "onpointerenter", "onpointerleave"
    , "onpointermove", "onpointerout", "onpointerup", "onstart", "onseeked"
    , "onprogress", "onreadystatechange", "onpropertychange", "onlosecapture"
    , "ontoggle", "onopen", "onclose", "onshow"
    ]


executableWords : List String
executableWords =
    [ "javascript", "vbscript", "mocha", "livescript"
    , "alert", "prompt", "confirm"
    , "documentcookie", "documenturl", "windowonerror", "throw"
    , "settimeout", "setinterval", "fetch", "xmlhttprequest"
    , "documentwrite", "innerhtml", "outerhtml", "insertadjacenthtml"
    ]


mediaWords : List String
mediaWords =
    [ "img", "image", "video", "audio", "source", "srcset", "poster" ]


htmlCarrierWords : List String
htmlCarrierWords =
    [ "script", "iframe", "object", "embed", "svg", "math"
    , "style", "form", "base", "meta"
    ]


encodedScriptSignals : List String
encodedScriptSignals =
    [ "java%0ascript", "java%09script", "java&#", "&#x6a"
    , "j&#x61;vascript", "&#106;avascript", "jav%61script"
    , "%6a%61%76%61%73%63%72%69%70%74"
    , "jav\tavascript", "jav\nascript"
    ]


countEntityOccurrences : String -> Int
countEntityOccurrences raw =
    List.length (String.indexes "&#" raw)

dedupeScoreItems : List ScoreItem -> List ScoreItem
dedupeScoreItems items =
    items
        |> List.foldl
            (\item acc ->
                if List.any (\x -> x.message == item.message) acc then acc
                else item :: acc
            )
            []
        |> List.reverse


attributeContext : String -> String -> String -> String
attributeContext tagName attrName attrValue =
    "<" ++ tagName ++ "> attribute " ++ attrName ++ "=\"" ++ String.left 40 attrValue ++ "\""


normalize : String -> String
normalize s =
    s
        |> String.toLower
        |> replaceMany
            [ ( "\n", " " ), ( "\r", " " ), ( "\t", " " )
            , ( "\"", "" ), ( "'", "" ), ( "`", "" )
            , ( "(", "" ), ( ")", "" ), ( "{", "" ), ( "}", "" )
            , ( "[", "" ), ( "]", "" ), ( ":", "" ), ( ";", "" )
            , ( ",", "" ), ( ".", "" ), ( "=", "" ), ( "\\", "" ), ( "/", "" )
            , ( "\u{0000}", "" ), ( "&#0;", "" ), ( "%00", "" )
            , ( "\u{000B}", " " )
            , ( "\u{000C}", " " )
            ]


replaceMany : List ( String, String ) -> String -> String
replaceMany replacements input =
    List.foldl (\( a, b ) acc -> String.replace a b acc) input replacements


containsAny : String -> List String -> Bool
containsAny haystack needles =
    List.any (\n -> String.contains n haystack) needles


isUrlLikeAttribute : String -> Bool
isUrlLikeAttribute name =
    List.member name
        [ "href", "src", "action", "formaction", "data", "poster"
        , "xlink:href", "lowsrc", "dynsrc", "background", "code", "codebase"
        ]


isDataHtmlPayload : String -> Bool
isDataHtmlPayload value =
    containsAny value
        [ "datatexthtml", "database64", "%3cscript"
        , "onerror", "onload", "phnjcmlwd"
        ]


renderExpression : List HtmlNode -> List Warning -> String
renderExpression nodes _ =
    nodes |> List.map (renderTree 0) |> String.join "\n"


renderExpressionNode : List HtmlNode -> List Warning -> String
renderExpressionNode = renderExpression


renderTree : Int -> HtmlNode -> String
renderTree indent node =
    let pad = String.repeat indent "  " in
    case node of
        Element elem ->
            pad ++ "<" ++ elem.tag ++ ">\n"
                ++ (elem.children |> List.map (renderTree (indent + 1)) |> String.join "\n")
        Text txt ->
            pad ++ "TEXT: " ++ String.left 40 txt.content
        Comment cmt ->
            pad ++ "COMMENT: " ++ String.left 40 cmt.content


renderRiskTree : List RiskNode -> String
renderRiskTree nodes =
    nodes |> List.map (renderRiskNode 0) |> String.join "\n"


renderRiskNode : Int -> RiskNode -> String
renderRiskNode indent (RiskNode rn) =
    let
        pad     = String.repeat indent "  "
        selfRisk =
            aggregateRisk rn.selfWarnings
        riskLbl =
            case selfRisk of
                Dangerous  -> "[D]"
                Suspicious -> "[S]"
                Safe       -> "[ ]"
        subtreeLbl =
            if selfRisk /= rn.aggregateRisk then
                case rn.aggregateRisk of
                    Dangerous  -> " [subtree:D]"
                    Suspicious -> " [subtree:S]"
                    Safe       -> ""
            else
                ""
        nodeLbl =
            case rn.node of
                Element elem -> "<" ++ elem.tag ++ ">"
                Text txt     -> "TEXT: " ++ String.left 30 txt.content
                Comment cmt  -> "COMMENT: " ++ String.left 30 cmt.content
        warnBlk =
            rn.selfWarnings
                |> List.map (\w -> pad ++ "  - " ++ w.message)
                |> String.join "\n"
        childBlk =
            rn.children
                |> List.map (renderRiskNode (indent + 1))
                |> String.join "\n"
    in
    String.join "\n"
        (List.filter (\s -> s /= "") [ pad ++ riskLbl ++ subtreeLbl ++ " " ++ nodeLbl, warnBlk, childBlk ])
