module DetoXSS.Core exposing
    ( SafeContent
    , SafeHtml
    , ValidatedInput
    , RawInput
    , Sanitized
    , Validated
    , Raw
    , fromRaw
    , fromValidated
    , fromSanitized
    , getContent
    , WhitelistState
    , defaultWhitelist
    , initWhitelist
    , enableWhitelist
    , disableWhitelist
    , setWhitelist
    , isWhitelistEnabled
    , isTagAllowed
    , isAttrAllowed
    )

{-| Shared types and helpers used by the DetoXSS package.

This module defines lightweight wrappers for raw, validated, and sanitized
content. The wrappers make the intended state of a value visible in type
signatures.

The module also provides convenience aliases and helpers for whitelist state
management.

@docs SafeContent, SafeHtml, ValidatedInput, RawInput

@docs Sanitized, Validated, Raw

@docs fromRaw, fromValidated, fromSanitized

@docs getContent

@docs WhitelistState

@docs defaultWhitelist, initWhitelist

@docs enableWhitelist, disableWhitelist, setWhitelist

@docs isWhitelistEnabled, isTagAllowed, isAttrAllowed

-}

import DetoXSS.Whitelist as WL


{-| Phantom marker for sanitized content.

Values marked with this state are intended to represent content that has already
gone through a sanitization step.
-}
type Sanitized
    = Sanitized


{-| Phantom marker for validated content.

Values marked with this state are intended to represent content that has passed
a validation step.
-}
type Validated
    = Validated


{-| Phantom marker for raw content.

Raw content should be treated as untrusted until it is validated, sanitized, or
otherwise processed according to its output context.
-}
type Raw
    = Raw


{-| A string wrapped with a phantom state.

The `state` parameter is used to distinguish raw, validated, and sanitized
values at the type level.
-}
type SafeContent state
    = SafeContent String


{-| Sanitized HTML-like content.

This alias is used for values that are intended to be safe to pass through the
DetoXSS API after sanitization.
-}
type alias SafeHtml =
    SafeContent Sanitized


{-| Validated input value.

This alias is used for values that passed validation rules, for example form
input validation.
-}
type alias ValidatedInput =
    SafeContent Validated


{-| Raw input value.

This alias is used for values that have not yet been validated or sanitized.
-}
type alias RawInput =
    SafeContent Raw


{-| Wrap a string as raw input.

This function does not validate or sanitize the value. It only marks the value
as raw at the type level.
-}
fromRaw : String -> RawInput
fromRaw str =
    SafeContent str


{-| Wrap a string as validated input.

This function does not perform validation by itself. It should be used only
after the caller has already validated the value.
-}
fromValidated : String -> ValidatedInput
fromValidated str =
    SafeContent str


{-| Wrap a string as sanitized content.

This function does not sanitize the value by itself. It should be used only
after the caller has already sanitized the value.

For actual sanitization, use functions from `DetoXSS.Sanitize`.
-}
fromSanitized : String -> SafeHtml
fromSanitized str =
    SafeContent str


{-| Extract the underlying string from a wrapped value.
-}
getContent : SafeContent state -> String
getContent (SafeContent str) =
    str


{-| Alias for the whitelist runtime state.
-}
type alias WhitelistState =
    WL.State


{-| Default whitelist configuration.
-}
defaultWhitelist : WL.Whitelist
defaultWhitelist =
    WL.defaultConfig


{-| Initial whitelist state.

The default whitelist configuration is loaded, but whitelist mode is disabled.
-}
initWhitelist : WhitelistState
initWhitelist =
    WL.initialState


{-| Enable whitelist mode.
-}
enableWhitelist : WhitelistState -> WhitelistState
enableWhitelist =
    WL.enable


{-| Disable whitelist mode.
-}
disableWhitelist : WhitelistState -> WhitelistState
disableWhitelist =
    WL.disable


{-| Replace the whitelist configuration.
-}
setWhitelist : WL.Whitelist -> WhitelistState -> WhitelistState
setWhitelist =
    WL.set


{-| Check whether whitelist mode is enabled.
-}
isWhitelistEnabled : WhitelistState -> Bool
isWhitelistEnabled =
    WL.isEnabled


{-| Check whether a tag is allowed by the whitelist state.
-}
isTagAllowed : WhitelistState -> String -> Bool
isTagAllowed =
    WL.isAllowedTag


{-| Check whether an attribute is allowed by the whitelist state.
-}
isAttrAllowed : WhitelistState -> String -> Bool
isAttrAllowed =
    WL.isAllowedAttribute