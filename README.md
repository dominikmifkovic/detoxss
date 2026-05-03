# DetoXSS

`DetoXSS` is an Elm package for safer handling of untrusted input in Elm applications.
It provides helpers for text escaping, simple HTML sanitization, URL validation, port input decoding, form validation, and static AST-based detection of XSS-like payloads.

The package is intended as a practical defensive layer. It does not guarantee complete protection against XSS in every browser/runtime context. The final safety of a value still depends on where and how it is used: as text, HTML, URL, attribute value, or data passed to JavaScript.

## What to use

Use the package according to the output context:

- Display plain user text with `DetoXSS.Sanitize.sanitizeText`.
- Allow a small subset of HTML with `DetoXSS.Sanitize.sanitizeWithWhitelist`.
- Validate URL values with `DetoXSS.Attributes.safeHref` or `safeSrc`.
- Detect XSS-like input with `DetoXSS.Ast.classifyBalanced` or `scanBalanced`.
- Decode data received from JavaScript ports with `DetoXSS.Port.inboundDecoder`.
- Validate form values with functions from `DetoXSS.Validate`.

## Escaping plain text

Use `sanitizeText` when the whole input should be shown as text and no HTML formatting should be preserved.

```elm
import Html exposing (Html, text)
import DetoXSS.Core exposing (getContent)
import DetoXSS.Sanitize exposing (sanitizeText)

viewComment : String -> Html msg
viewComment userInput =
    userInput
        |> sanitizeText
        |> getContent
        |> text
```

For example, an input such as `<script>alert(1)</script>` is escaped and displayed as ordinary text.

## Sanitizing simple HTML

Use `sanitizeWithWhitelist` when the application should allow a small and explicit subset of HTML.

```elm
import DetoXSS.Core exposing (getContent)
import DetoXSS.Sanitize exposing (sanitizeWithWhitelist)
import DetoXSS.Whitelist as WL

commentWhitelist : WL.State
commentWhitelist =
    WL.initialState
        |> WL.set (WL.fromLists [ "b", "i", "strong", "em", "br" ] [])
        |> WL.enable

safeHtml : String
safeHtml =
    userInput
        |> sanitizeWithWhitelist commentWhitelist
        |> getContent
```

When the whitelist is enabled, only allowed tags and attributes are preserved. When it is disabled, the input is treated as plain text.

The whitelist is not a way to allow arbitrary active HTML. Some risky elements and attributes are blocked regardless of configuration, for example script-like tags, inline event handlers such as `onclick` or `onerror`, and dangerous URL schemes such as `javascript:`.

## Allowing links

If links should be preserved, allow the `a` tag, the `href` attribute, and a small set of URL schemes.

```elm
import DetoXSS.Whitelist as WL

linkWhitelist : WL.State
linkWhitelist =
    WL.initialState
        |> WL.set
            (WL.fromAllFull
                [ "p", "strong", "em", "a" ]
                [ "href", "title" ]
                [ "href" ]
                [ "http:", "https:", "mailto:" ]
            )
        |> WL.enable
```

Keep the whitelist as small as possible. Only allow tags, attributes, and schemes that the application really needs.

## Validating URL attributes

Use `safeHref` for links and `safeSrc` for media sources.

```elm
import Html exposing (Html, a, text)
import Html.Attributes exposing (href)
import DetoXSS.Attributes exposing (safeHref)
import DetoXSS.Core exposing (getContent)

viewLink : String -> Html msg
viewLink userUrl =
    let
        ( accepted, safeUrl ) =
            safeHref userUrl
    in
    if accepted then
        a [ href (getContent safeUrl) ] [ text "Open link" ]

    else
        text "Invalid link"
```

If the URL is unsafe, the function returns `False` and a safe fallback value.

## Detecting XSS-like payloads with AST analysis

The AST analyzer does not rewrite the input. It classifies it as `Safe`, `Suspicious`, or `Dangerous`.

```elm
import DetoXSS.Ast as Ast

case Ast.classifyBalanced userInput of
    Ast.Safe ->
        "Safe input"

    Ast.Suspicious ->
        "Suspicious input"

    Ast.Dangerous ->
        "Dangerous input"
```

Use `scanBalanced` when the application also needs the reasons for the decision.

```elm
import DetoXSS.Ast as Ast

warnings : List Ast.Warning
warnings =
    Ast.scanBalanced userInput
```

Each warning contains a risk level and a short explanation.

## AST handling policies

`DetoXSS.Ast` only classifies input. The application decides what to do with the result. A common approach is to define a small policy layer.

```elm
import DetoXSS.Ast as Ast
import DetoXSS.Core exposing (SafeHtml)
import DetoXSS.Sanitize exposing (sanitizeWithWhitelist)
import DetoXSS.Whitelist as WL

type AstPolicy
    = AllowWithSanitization
    | RejectDangerous

processWithAstPolicy : AstPolicy -> WL.State -> String -> Maybe SafeHtml
processWithAstPolicy policy whitelistState input =
    let
        risk =
            Ast.classifyBalanced input

        sanitized =
            sanitizeWithWhitelist whitelistState input
    in
    case policy of
        AllowWithSanitization ->
            Just sanitized

        RejectDangerous ->
            case risk of
                Ast.Dangerous ->
                    Nothing

                Ast.Suspicious ->
                    Just sanitized

                Ast.Safe ->
                    Just sanitized
```

`AllowWithSanitization` is useful when the application wants to keep the value but still sanitize it. `RejectDangerous` blocks inputs that the analyzer marks as clearly dangerous.

For stricter applications, a third policy can also reject `Suspicious` values.

## Combining AST analysis and sanitization

AST analysis and sanitization solve different problems:

- AST analysis answers: “Does this input look risky?”
- Sanitization answers: “How should this input be transformed before use?”

In security-sensitive places, use both.

```elm
import DetoXSS.Ast as Ast
import DetoXSS.Core exposing (SafeHtml)
import DetoXSS.Sanitize exposing (sanitizeText)

processInput : String -> Maybe SafeHtml
processInput input =
    case Ast.classifyBalanced input of
        Ast.Dangerous ->
            Nothing

        Ast.Suspicious ->
            Just (sanitizeText input)

        Ast.Safe ->
            Just (sanitizeText input)
```

## Handling data from JavaScript ports

Data received through ports should be treated as untrusted. Use `inboundDecoder` to decode and limit incoming values.

```elm
import DetoXSS.Port as SafePort
import DetoXSS.Whitelist as WL
import Json.Decode as Decode

decoder : Decode.Decoder SafePort.Inbound
decoder =
    SafePort.inboundDecoder (WL.initialState |> WL.enable)
```

The decoder expects objects with a `type` and a `value`, for example:

```json
{
  "type": "html",
  "value": "<img src=x onerror=alert(1)>"
}
```

The port decoder is responsible for controlled decoding, input size limits, and context-specific processing. If the application also needs AST classification, call `DetoXSS.Ast` explicitly and apply an application-level policy.

Be careful when sending data back to JavaScript. A value that is safe in Elm can still become dangerous if JavaScript inserts it into an unsafe DOM sink such as `innerHTML`.

## Validating forms

Validation checks whether a value has the expected format. It is not a replacement for sanitization or AST analysis.

```elm
import DetoXSS.Validate exposing (validateEmail)

case validateEmail emailInput of
    Ok validEmail ->
        "Valid e-mail"

    Err errors ->
        "Invalid e-mail"
```

Custom validators can be built from rules.

```elm
import DetoXSS.Validate exposing (validate, nonEmpty, minLength, maxLength)

validateProjectName =
    validate
        [ nonEmpty
        , minLength 3
        , maxLength 40
        ]
```

## Recommended workflow

1. Treat all external input as untrusted.
2. Decide where the value will be used.
3. Use `sanitizeText` for plain text output.
4. Use `sanitizeWithWhitelist` for limited HTML.
5. Use `safeHref` or `safeSrc` for URL attributes.
6. Use `classifyBalanced` or `scanBalanced` when the application needs XSS detection.
7. Apply an AST policy such as `AllowWithSanitization` or `RejectDangerous`.
8. Treat port data as untrusted even if it comes from your own JavaScript code.
9. Avoid unsafe JavaScript DOM sinks such as `innerHTML` unless the value has been processed for that context.

`DetoXSS` is most useful as part of a layered approach: AST detection, sanitization, whitelist rules, URL validation, form validation, and careful port handling should complement each other.
