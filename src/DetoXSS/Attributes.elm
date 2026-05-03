module DetoXSS.Attributes exposing
    ( safeHref
    , safeSrc
    , safeHrefW
    , safeSrcW
    , defaultSchemes
    )

{-| Helpers for validating URL-like attribute values.

This module is intended for values used in attributes such as `href` or `src`.
It checks whether a URL uses an allowed scheme and returns a validated value
or a safe fallback.

For custom scheme lists, use the whitelist-aware variants.

@docs safeHref, safeSrc

@docs safeHrefW, safeSrcW

@docs defaultSchemes

-}

import Char
import DetoXSS.Core exposing (ValidatedInput, fromValidated)
import DetoXSS.Sanitize exposing (sanitizeForAttribute)
import DetoXSS.Whitelist as WL

{-| Default URL schemes accepted by `safeHref` and `safeSrc`.

The list contains common non-script schemes.
-}
defaultSchemes : List String
defaultSchemes =
    [ "http:", "https:", "mailto:", "tel:" ]

{-| Validate a value intended for an `href` attribute.

The function returns a pair. The first value says whether the URL was accepted.
The second value contains a validated URL value or a safe fallback.

    safeHref "https://example.com"
    safeHref "javascript:alert(1)"

-}
safeHref : String -> ( Bool, ValidatedInput )
safeHref =
    validateUrlWithSchemes defaultSchemes

{-| Validate a value intended for a `src` attribute.

The function returns a pair. The first value says whether the URL was accepted.
The second value contains a validated URL value or a safe fallback.

    safeSrc "https://example.com/image.png"
    safeSrc "javascript:alert(1)"

-}
safeSrc : String -> ( Bool, ValidatedInput )
safeSrc =
    validateUrlWithSchemes defaultSchemes

{-| Validate a value intended for an `href` attribute using whitelist schemes.

The allowed schemes are taken from the provided whitelist state.
-}
safeHrefW : WL.State -> String -> ( Bool, ValidatedInput )
safeHrefW state url =
    validateUrlWithSchemes (WL.getAllowedSchemes state) url

{-| Validate a value intended for a `src` attribute using whitelist schemes.

The allowed schemes are taken from the provided whitelist state.
-}
safeSrcW : WL.State -> String -> ( Bool, ValidatedInput )
safeSrcW state url =
    validateUrlWithSchemes (WL.getAllowedSchemes state) url


validateUrlWithSchemes : List String -> String -> ( Bool, ValidatedInput )
validateUrlWithSchemes schemes rawUrl =
    let
        cleaned =
            rawUrl
                |> String.trim
                |> stripInvisible
                |> sanitizeForAttribute

        normalized =
            cleaned
                |> DetoXSS.Core.getContent
                |> String.trim
                |> String.toLower
    in
    if isAllowedUrl schemes normalized then
        ( True, cleaned )

    else
        ( False, fromValidated "#" )


isAllowedUrl : List String -> String -> Bool
isAllowedUrl schemes url =
    if url == "" then
        True

    else if String.startsWith "#" url then
        True

    else if String.startsWith "/" url then
        True

    else if String.startsWith "./" url || String.startsWith "../" url then
        True

    else
        case extractLeadingScheme url of
            Nothing ->
                True

            Just scheme ->
                List.member scheme schemes


extractLeadingScheme : String -> Maybe String
extractLeadingScheme url =
    let
        chars =
            String.toList url

        isSchemeChar c =
            Char.isAlphaNum c || c == '+' || c == '-' || c == '.'

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
                    if List.isEmpty consumed then
                        if Char.isAlpha c then
                            step [ c ] rest
                        else
                            Nothing
                    else if isSchemeChar c then
                        step (c :: consumed) rest
                    else
                        Nothing
    in
    step [] chars


stripInvisible : String -> String
stripInvisible =
    String.filter
        (\c ->
            let
                code =
                    Char.toCode c
            in
            code >= 32 || c == '\n' || c == '\r' || c == '\t'
        )