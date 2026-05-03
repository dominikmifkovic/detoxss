module DetoXSS.Port exposing
    ( maxChars
    , maxListLen
    , AnalysisPolicy(..)
    , HtmlResult
    , Inbound(..)
    , UrlResult
    , inboundDecoder
    , inboundDecoderAnalyzed
    , rawDecoderCapped
    , validatedAttrDecoder
    , safeHtmlDecoderW
    , safeHtmlDecoderAnalyzedW
    , safeHtmlResultDecoderW
    , safeHtmlListDecoderW
    , safeHtmlListDecoderAnalyzedW
    , urlDecoderW
    , analyzeRawHtml
    , encodeRisk
    , encodeHtmlResult
    , encodeSafeHtml
    , encodeSafeHtmlList
    , encodeValidated
    , encodeValidatedList
    , encodeUrlResult
    , normalizeNewlines
    , stripControl
    )

import DetoXSS.Ast as Ast
import DetoXSS.Attributes as Attrs
import DetoXSS.Core as Core exposing (RawInput, SafeHtml, ValidatedInput, getContent)
import DetoXSS.Sanitize as Sanitize
import DetoXSS.Whitelist as WL
import Json.Decode as Decode exposing (Decoder)
import Json.Encode as Encode


maxChars : Int
maxChars =
    100000


maxListLen : Int
maxListLen =
    512


stripControl : String -> String
stripControl =
    Sanitize.stripControl


normalizeNewlines : String -> String
normalizeNewlines s =
    s
        |> String.replace "\r\n" "\n"
        |> String.replace "\r" "\n"


normalizeAndStrip : String -> String
normalizeAndStrip s =
    s
        |> normalizeNewlines
        |> stripControl


{-| Policy used by AST-aware port decoders.

  - `AllowAfterSanitize` keeps the previous behaviour, but still reports the AST risk
    through `safeHtmlResultDecoderW`.
  - `RejectDangerous` rejects only inputs classified as `Dangerous`.
  - `RejectSuspiciousAndDangerous` rejects both `Suspicious` and `Dangerous` inputs.

-}
type AnalysisPolicy
    = AllowAfterSanitize
    | RejectDangerous
    | RejectSuspiciousAndDangerous


type alias HtmlResult =
    { ok : Bool
    , risk : Ast.Risk
    , value : SafeHtml
    , reason : String
    }


type alias UrlResult =
    { ok : Bool
    , value : ValidatedInput
    }


type Inbound
    = InHtml SafeHtml
    | InAttr ValidatedInput
    | InUrl UrlResult
    | InHtmlList (List SafeHtml)


inboundDecoder : WL.State -> Decoder Inbound
inboundDecoder wlState =
    Decode.field "type" Decode.string
        |> Decode.andThen
            (\tag ->
                case tag of
                    "html" ->
                        Decode.field "value" (Decode.string |> Decode.andThen (mapToHtml wlState))
                            |> Decode.map InHtml

                    "attr" ->
                        Decode.field "value" (Decode.string |> Decode.andThen mapToAttr)
                            |> Decode.map InAttr

                    "url" ->
                        Decode.field "value" (Decode.string |> Decode.andThen (mapToUrl wlState))
                            |> Decode.map InUrl

                    "html-list" ->
                        Decode.field "value" (Decode.list Decode.string |> Decode.andThen (mapToHtmlList wlState))
                            |> Decode.map InHtmlList

                    _ ->
                        Decode.fail "unknown inbound type"
            )


inboundDecoderAnalyzed : AnalysisPolicy -> WL.State -> Decoder Inbound
inboundDecoderAnalyzed policy wlState =
    Decode.field "type" Decode.string
        |> Decode.andThen
            (\tag ->
                case tag of
                    "html" ->
                        Decode.field "value" (Decode.string |> Decode.andThen (mapToHtmlAnalyzed policy wlState))
                            |> Decode.map InHtml

                    "attr" ->
                        Decode.field "value" (Decode.string |> Decode.andThen mapToAttr)
                            |> Decode.map InAttr

                    "url" ->
                        Decode.field "value" (Decode.string |> Decode.andThen (mapToUrl wlState))
                            |> Decode.map InUrl

                    "html-list" ->
                        Decode.field "value" (Decode.list Decode.string |> Decode.andThen (mapToHtmlListAnalyzed policy wlState))
                            |> Decode.map InHtmlList

                    _ ->
                        Decode.fail "unknown inbound type"
            )


rawDecoderCapped : Decoder RawInput
rawDecoderCapped =
    Decode.string
        |> Decode.andThen
            (\s ->
                let
                    cleaned =
                        normalizeAndStrip s
                in
                if String.length cleaned > maxChars then
                    Decode.fail "input exceeds maxChars"

                else
                    Decode.succeed (Core.fromRaw cleaned)
            )


validatedAttrDecoder : Decoder ValidatedInput
validatedAttrDecoder =
    Decode.string
        |> Decode.andThen mapToAttr


safeHtmlDecoderW : WL.State -> Decoder SafeHtml
safeHtmlDecoderW wlState =
    Decode.string
        |> Decode.andThen (mapToHtml wlState)


safeHtmlDecoderAnalyzedW : AnalysisPolicy -> WL.State -> Decoder SafeHtml
safeHtmlDecoderAnalyzedW policy wlState =
    Decode.string
        |> Decode.andThen (mapToHtmlAnalyzed policy wlState)


safeHtmlResultDecoderW : AnalysisPolicy -> WL.State -> Decoder HtmlResult
safeHtmlResultDecoderW policy wlState =
    Decode.string
        |> Decode.andThen (mapToHtmlResult policy wlState)


safeHtmlListDecoderW : WL.State -> Decoder (List SafeHtml)
safeHtmlListDecoderW wlState =
    Decode.list Decode.string
        |> Decode.andThen (mapToHtmlList wlState)


safeHtmlListDecoderAnalyzedW : AnalysisPolicy -> WL.State -> Decoder (List SafeHtml)
safeHtmlListDecoderAnalyzedW policy wlState =
    Decode.list Decode.string
        |> Decode.andThen (mapToHtmlListAnalyzed policy wlState)


urlDecoderW : WL.State -> Decoder UrlResult
urlDecoderW wlState =
    Decode.string
        |> Decode.andThen (mapToUrl wlState)


analyzeRawHtml : String -> Ast.Risk
analyzeRawHtml raw =
    raw
        |> normalizeAndStrip
        |> Ast.classifyBalanced


encodeRisk : Ast.Risk -> Encode.Value
encodeRisk risk =
    Encode.string (riskToString risk)


encodeHtmlResult : HtmlResult -> Encode.Value
encodeHtmlResult result =
    Encode.object
        [ ( "ok", Encode.bool result.ok )
        , ( "risk", encodeRisk result.risk )
        , ( "value", Encode.string (getContent result.value) )
        , ( "reason", Encode.string result.reason )
        ]


encodeSafeHtml : SafeHtml -> Encode.Value
encodeSafeHtml sh =
    Encode.string (getContent sh)


encodeSafeHtmlList : List SafeHtml -> Encode.Value
encodeSafeHtmlList lst =
    lst
        |> List.map (getContent >> Encode.string)
        |> Encode.list identity


encodeValidated : ValidatedInput -> Encode.Value
encodeValidated v =
    Encode.string (getContent v)


encodeValidatedList : List ValidatedInput -> Encode.Value
encodeValidatedList xs =
    xs
        |> List.map (getContent >> Encode.string)
        |> Encode.list identity


encodeUrlResult : UrlResult -> Encode.Value
encodeUrlResult r =
    Encode.object
        [ ( "ok", Encode.bool r.ok )
        , ( "value", Encode.string (getContent r.value) )
        ]


mapToHtml : WL.State -> String -> Decoder SafeHtml
mapToHtml wlState s =
    let
        cleaned =
            normalizeAndStrip s
    in
    if String.length cleaned > maxChars then
        Decode.fail "html input exceeds maxChars"

    else
        Decode.succeed (Sanitize.sanitizeWithWhitelist wlState cleaned)


mapToHtmlAnalyzed : AnalysisPolicy -> WL.State -> String -> Decoder SafeHtml
mapToHtmlAnalyzed policy wlState s =
    let
        cleaned =
            normalizeAndStrip s
    in
    if String.length cleaned > maxChars then
        Decode.fail "html input exceeds maxChars"

    else
        let
            risk =
                Ast.classifyBalanced cleaned
        in
        if shouldReject policy risk then
            Decode.fail ("html rejected by AST analysis: " ++ riskToString risk)

        else
            Decode.succeed (Sanitize.sanitizeWithWhitelist wlState cleaned)


mapToHtmlResult : AnalysisPolicy -> WL.State -> String -> Decoder HtmlResult
mapToHtmlResult policy wlState s =
    let
        cleaned =
            normalizeAndStrip s
    in
    if String.length cleaned > maxChars then
        Decode.fail "html input exceeds maxChars"

    else
        let
            risk =
                Ast.classifyBalanced cleaned

            rejected =
                shouldReject policy risk

            reason =
                if rejected then
                    "rejected by AST analysis: " ++ riskToString risk

                else
                    "accepted by AST analysis: " ++ riskToString risk
        in
        Decode.succeed
            { ok = not rejected
            , risk = risk
            , value = Sanitize.sanitizeWithWhitelist wlState cleaned
            , reason = reason
            }


mapToAttr : String -> Decoder ValidatedInput
mapToAttr s =
    let
        cleaned =
            normalizeAndStrip s
    in
    if String.length cleaned > maxChars then
        Decode.fail "attribute input exceeds maxChars"

    else
        Decode.succeed (Sanitize.sanitizeForAttribute cleaned)


mapToUrl : WL.State -> String -> Decoder UrlResult
mapToUrl wlState s =
    let
        cleaned =
            normalizeAndStrip s
    in
    if String.length cleaned > maxChars then
        Decode.fail "url input exceeds maxChars"

    else
        let
            ( ok, v ) =
                Attrs.safeHrefW wlState cleaned
        in
        Decode.succeed { ok = ok, value = v }


mapToHtmlList : WL.State -> List String -> Decoder (List SafeHtml)
mapToHtmlList wlState xs =
    if List.length xs > maxListLen then
        Decode.fail "html list exceeds maxListLen"

    else
        let
            cleaned =
                List.map normalizeAndStrip xs

            tooLong =
                List.any (\item -> String.length item > maxChars) cleaned
        in
        if tooLong then
            Decode.fail "one or more html list items exceed maxChars"

        else
            cleaned
                |> List.map (Sanitize.sanitizeWithWhitelist wlState)
                |> Decode.succeed


mapToHtmlListAnalyzed : AnalysisPolicy -> WL.State -> List String -> Decoder (List SafeHtml)
mapToHtmlListAnalyzed policy wlState xs =
    if List.length xs > maxListLen then
        Decode.fail "html list exceeds maxListLen"

    else
        case analyzeAndSanitizeList policy wlState 0 xs [] of
            Ok items ->
                Decode.succeed items

            Err message ->
                Decode.fail message


analyzeAndSanitizeList : AnalysisPolicy -> WL.State -> Int -> List String -> List SafeHtml -> Result String (List SafeHtml)
analyzeAndSanitizeList policy wlState index remaining acc =
    case remaining of
        [] ->
            Ok (List.reverse acc)

        raw :: rest ->
            let
                cleaned =
                    normalizeAndStrip raw
            in
            if String.length cleaned > maxChars then
                Err ("html list item " ++ String.fromInt index ++ " exceeds maxChars")

            else
                let
                    risk =
                        Ast.classifyBalanced cleaned
                in
                if shouldReject policy risk then
                    Err ("html list item " ++ String.fromInt index ++ " rejected by AST analysis: " ++ riskToString risk)

                else
                    analyzeAndSanitizeList
                        policy
                        wlState
                        (index + 1)
                        rest
                        (Sanitize.sanitizeWithWhitelist wlState cleaned :: acc)


shouldReject : AnalysisPolicy -> Ast.Risk -> Bool
shouldReject policy risk =
    case policy of
        AllowAfterSanitize ->
            False

        RejectDangerous ->
            risk == Ast.Dangerous

        RejectSuspiciousAndDangerous ->
            risk == Ast.Dangerous || risk == Ast.Suspicious


riskToString : Ast.Risk -> String
riskToString risk =
    case risk of
        Ast.Safe ->
            "safe"

        Ast.Suspicious ->
            "suspicious"

        Ast.Dangerous ->
            "dangerous"
