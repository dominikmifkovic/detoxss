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

{-| JSON decoders and encoders for values crossing Elm ports.

Ports are a trust boundary between Elm and JavaScript. Values received through
ports should be treated as untrusted. This module provides capped decoders for
HTML-like values, attribute values, URL values, and lists of sanitized HTML
values.

The analyzed decoders combine port decoding with `DetoXSS.Ast` classification
and an application-level analysis policy.

@docs Inbound, UrlResult, AnalysisPolicy, HtmlResult

@docs inboundDecoder, inboundDecoderAnalyzed

@docs rawDecoderCapped, validatedAttrDecoder

@docs safeHtmlDecoderW, safeHtmlDecoderAnalyzedW, safeHtmlResultDecoderW

@docs safeHtmlListDecoderW, safeHtmlListDecoderAnalyzedW

@docs urlDecoderW

@docs analyzeRawHtml

@docs encodeRisk, encodeHtmlResult

@docs encodeSafeHtml, encodeSafeHtmlList

@docs encodeValidated, encodeValidatedList

@docs encodeUrlResult

@docs maxChars, maxListLen

@docs normalizeNewlines, stripControl

-}

import DetoXSS.Ast as Ast
import DetoXSS.Attributes as Attrs
import DetoXSS.Core as Core exposing (RawInput, SafeHtml, ValidatedInput, getContent)
import DetoXSS.Sanitize as Sanitize
import DetoXSS.Whitelist as WL
import Json.Decode as Decode exposing (Decoder)
import Json.Encode as Encode

{-| Maximum number of characters accepted by capped port decoders.
-}
maxChars : Int
maxChars =
    100000

{-| Maximum number of items accepted by list decoders.
-}
maxListLen : Int
maxListLen =
    512

{-| Remove control characters from a string.

Newline, carriage return, and tab characters are preserved.
-}
stripControl : String -> String
stripControl =
    Sanitize.stripControl

{-| Normalize newline characters.

This converts Windows and old Mac line endings to `\n`.
-}
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


{-| Policy used by analyzed port decoders.

`AllowAfterSanitize` always allows the value after sanitization.
`RejectDangerous` rejects values classified as `Dangerous`.
`RejectSuspiciousAndDangerous` rejects values classified as `Suspicious` or
`Dangerous`.
-}
type AnalysisPolicy
    = AllowAfterSanitize
    | RejectDangerous
    | RejectSuspiciousAndDangerous

{-| Result of analyzing and sanitizing an HTML-like value.

The record contains whether the value was accepted, the AST risk level, the
sanitized value, and a human-readable reason.
-}
type alias HtmlResult =
    { ok : Bool
    , risk : Ast.Risk
    , value : SafeHtml
    , reason : String
    }

{-| Result of validating a URL-like value from a port.

`ok` says whether the value was accepted. `value` contains either the accepted
URL or a safe fallback.
-}
type alias UrlResult =
    { ok : Bool
    , value : ValidatedInput
    }

{-| Values that can be received through the generic inbound port decoder.

The constructors distinguish sanitized HTML-like values, validated attribute
values, URL validation results, and lists of sanitized HTML-like values.
-}
type Inbound
    = InHtml SafeHtml
    | InAttr ValidatedInput
    | InUrl UrlResult
    | InHtmlList (List SafeHtml)

{-| Decode an inbound JSON value from a port.

The decoder expects an object with a `type` field and a `value` field. The
`type` field decides whether the value is treated as HTML-like content,
attribute content, URL content, or a list of HTML-like values.
-}
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

{-| Decode inbound port data and apply AST analysis for HTML-like values.

The provided policy controls whether suspicious or dangerous values are accepted
or rejected. Non-HTML values are decoded using the same rules as
`inboundDecoder`.
-}
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

{-| Decode a raw string with length limiting.

The decoder fails if the value exceeds `maxChars`.
-}
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

{-| Decode an attribute-like string and wrap it as validated input.
-}
validatedAttrDecoder : Decoder ValidatedInput
validatedAttrDecoder =
    Decode.string
        |> Decode.andThen mapToAttr

{-| Decode an HTML-like string and sanitize it with a whitelist state.
-}
safeHtmlDecoderW : WL.State -> Decoder SafeHtml
safeHtmlDecoderW wlState =
    Decode.string
        |> Decode.andThen (mapToHtml wlState)

{-| Decode a single HTML-like string with whitelist sanitization and AST policy.

If the policy rejects the detected risk level, decoding fails.
-}
safeHtmlDecoderAnalyzedW : AnalysisPolicy -> WL.State -> Decoder SafeHtml
safeHtmlDecoderAnalyzedW policy wlState =
    Decode.string
        |> Decode.andThen (mapToHtmlAnalyzed policy wlState)

{-| Decode a single HTML-like string and return an analysis result.

Unlike `safeHtmlDecoderAnalyzedW`, this decoder returns a structured
`HtmlResult` containing the risk and rejection reason instead of only returning
the sanitized value.
-}
safeHtmlResultDecoderW : AnalysisPolicy -> WL.State -> Decoder HtmlResult
safeHtmlResultDecoderW policy wlState =
    Decode.string
        |> Decode.andThen (mapToHtmlResult policy wlState)

{-| Decode a list of HTML-like strings and sanitize every item.

The decoder fails if the list exceeds `maxListLen`.
-}
safeHtmlListDecoderW : WL.State -> Decoder (List SafeHtml)
safeHtmlListDecoderW wlState =
    Decode.list Decode.string
        |> Decode.andThen (mapToHtmlList wlState)

{-| Decode a list of HTML-like strings with whitelist sanitization and AST policy.

If any item is rejected by the policy, the whole decoder fails.
-}
safeHtmlListDecoderAnalyzedW : AnalysisPolicy -> WL.State -> Decoder (List SafeHtml)
safeHtmlListDecoderAnalyzedW policy wlState =
    Decode.list Decode.string
        |> Decode.andThen (mapToHtmlListAnalyzed policy wlState)

{-| Decode a URL-like string and validate it with whitelist URL schemes.
-}
urlDecoderW : WL.State -> Decoder UrlResult
urlDecoderW wlState =
    Decode.string
        |> Decode.andThen (mapToUrl wlState)

{-| Analyze and sanitize a raw HTML-like string.

This helper is useful when an application already has a raw string and wants to
apply the same AST policy and whitelist sanitization logic used by the analyzed
port decoders.
-}
analyzeRawHtml : String -> Ast.Risk
analyzeRawHtml raw =
    raw
        |> normalizeAndStrip
        |> Ast.classifyBalanced

{-| Encode an AST risk value as a JSON string.

The output is one of `"safe"`, `"suspicious"`, or `"dangerous"`.
-}
encodeRisk : Ast.Risk -> Encode.Value
encodeRisk risk =
    Encode.string (riskToString risk)

{-| Encode an `HtmlResult` as JSON.

This is useful for sending analysis results back to JavaScript through an
outbound port.
-}
encodeHtmlResult : HtmlResult -> Encode.Value
encodeHtmlResult result =
    Encode.object
        [ ( "ok", Encode.bool result.ok )
        , ( "risk", encodeRisk result.risk )
        , ( "value", Encode.string (getContent result.value) )
        , ( "reason", Encode.string result.reason )
        ]

{-| Encode sanitized HTML-like content for an outbound port.
-}
encodeSafeHtml : SafeHtml -> Encode.Value
encodeSafeHtml sh =
    Encode.string (getContent sh)

{-| Encode a list of sanitized HTML-like values for an outbound port.
-}
encodeSafeHtmlList : List SafeHtml -> Encode.Value
encodeSafeHtmlList lst =
    lst
        |> List.map (getContent >> Encode.string)
        |> Encode.list identity

{-| Encode validated input for an outbound port.
-}
encodeValidated : ValidatedInput -> Encode.Value
encodeValidated v =
    Encode.string (getContent v)

{-| Encode a list of validated input values for an outbound port.
-}
encodeValidatedList : List ValidatedInput -> Encode.Value
encodeValidatedList xs =
    xs
        |> List.map (getContent >> Encode.string)
        |> Encode.list identity

{-| Encode a URL validation result for an outbound port.
-}
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
