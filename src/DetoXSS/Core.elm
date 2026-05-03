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

import DetoXSS.Whitelist as WL


type Sanitized
    = Sanitized


type Validated
    = Validated


type Raw
    = Raw


type SafeContent state
    = SafeContent String


type alias SafeHtml =
    SafeContent Sanitized


type alias ValidatedInput =
    SafeContent Validated


type alias RawInput =
    SafeContent Raw


fromRaw : String -> RawInput
fromRaw str =
    SafeContent str


fromValidated : String -> ValidatedInput
fromValidated str =
    SafeContent str


fromSanitized : String -> SafeHtml
fromSanitized str =
    SafeContent str


getContent : SafeContent state -> String
getContent (SafeContent str) =
    str


type alias WhitelistState =
    WL.State


defaultWhitelist : WL.Whitelist
defaultWhitelist =
    WL.defaultConfig


initWhitelist : WhitelistState
initWhitelist =
    WL.initialState


enableWhitelist : WhitelistState -> WhitelistState
enableWhitelist =
    WL.enable


disableWhitelist : WhitelistState -> WhitelistState
disableWhitelist =
    WL.disable


setWhitelist : WL.Whitelist -> WhitelistState -> WhitelistState
setWhitelist =
    WL.set


isWhitelistEnabled : WhitelistState -> Bool
isWhitelistEnabled =
    WL.isEnabled


isTagAllowed : WhitelistState -> String -> Bool
isTagAllowed =
    WL.isAllowedTag


isAttrAllowed : WhitelistState -> String -> Bool
isAttrAllowed =
    WL.isAllowedAttribute