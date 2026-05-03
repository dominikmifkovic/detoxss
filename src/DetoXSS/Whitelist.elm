module DetoXSS.Whitelist exposing
    ( State
    , Whitelist
    , defaultConfig
    , initialState
    , enable
    , disable
    , isEnabled
    , set
    , get
    , fromLists
    , fromAll
    , fromAllFull
    , isAllowedTag
    , isAllowedAttribute
    , isUrlAttribute
    , getAll
    , getAllFull
    , getAllowedSchemes
    , setAttributes
    , setUrlAttributes
    , setSchemes
    , blockedTags
    , blockedAttributes
    , blockedSchemes
    , isBlockedTag
    , isBlockedAttribute
    , isBlockedScheme
    )

{-| Whitelist configuration for controlled HTML sanitization.

A whitelist defines which tags, attributes, URL attributes, and URL schemes may
be preserved by `DetoXSS.Sanitize.sanitizeWithWhitelist`.

The whitelist is intended for allowing a small, explicit set of safe formatting
features. It is not meant to allow arbitrary active HTML content. Some dangerous
tags, attributes, and schemes are blocked regardless of the custom whitelist.

@docs State, Whitelist

@docs defaultConfig, initialState

@docs enable, disable, isEnabled

@docs set, get

@docs fromLists, fromAll, fromAllFull

@docs isAllowedTag, isAllowedAttribute, isUrlAttribute

@docs getAll, getAllFull, getAllowedSchemes

@docs setAttributes, setUrlAttributes, setSchemes

@docs blockedTags, blockedAttributes, blockedSchemes

@docs isBlockedTag, isBlockedAttribute, isBlockedScheme

-}

import Char exposing (isAlphaNum)


{-| Whitelist configuration used by `sanitizeWithWhitelist`.

The configuration contains four lists:

  - `tags` are HTML tag names that may be preserved.
  - `attributes` are attribute names that may be preserved.
  - `urlAttributes` are attributes whose values should be treated as URLs.
  - `allowedSchemes` are URL schemes accepted in URL-like attributes.

The configuration is normalized when it is created through helper functions such
as `fromLists`, `fromAll`, or `fromAllFull`.
-}
type alias Whitelist =
    { tags : List String
    , attributes : List String
    , urlAttributes : List String
    , allowedSchemes : List String
    }


{-| Runtime state of whitelist sanitization.

The `active` field controls whether whitelist mode is enabled. When whitelist
mode is disabled, sanitization treats the whole input as text instead of
preserving HTML tags.
-}
type alias State =
    { active : Bool
    , config : Whitelist
    }


{-| Default whitelist configuration.

It allows a small set of common formatting tags, link and image attributes, and
common URL schemes such as `http:`, `https:`, `mailto:`, and `tel:`.
-}
defaultConfig : Whitelist
defaultConfig =
    { tags =
        [ "b"
        , "i"
        , "u"
        , "em"
        , "strong"
        , "br"
        , "p"
        , "ul"
        , "ol"
        , "li"
        , "pre"
        , "code"
        , "blockquote"
        , "a"
        , "img"
        ]
    , attributes =
        [ "href"
        , "title"
        , "alt"
        , "src"
        ]
    , urlAttributes =
        [ "href"
        , "src"
        ]
    , allowedSchemes =
        [ "http:"
        , "https:"
        , "mailto:"
        , "tel:"
        ]
    }


{-| Initial whitelist state.

The default configuration is loaded, but whitelist mode is disabled.

Use `enable` to activate whitelist-based sanitization.
-}
initialState : State
initialState =
    { active = False
    , config = defaultConfig
    }


{-| Enable whitelist-based sanitization.

When enabled, `sanitizeWithWhitelist` may preserve allowed tags and attributes.
-}
enable : State -> State
enable st =
    { st | active = True }


{-| Disable whitelist-based sanitization.

When disabled, `sanitizeWithWhitelist` treats the whole input as text.
-}
disable : State -> State
disable st =
    { st | active = False }


{-| Check whether whitelist mode is enabled.
-}
isEnabled : State -> Bool
isEnabled st =
    st.active


{-| Replace the current whitelist configuration.

The configuration is normalized before being stored. Blocked tags, blocked
attributes, and blocked schemes are removed during normalization.
-}
set : Whitelist -> State -> State
set cfg st =
    { st | config = normalize cfg }


{-| Get allowed tags and attributes from the current state.
-}
get : State -> { tags : List String, attributes : List String }
get st =
    { tags = st.config.tags
    , attributes = st.config.attributes
    }


{-| Get allowed tags, attributes, and URL schemes from the current state.
-}
getAll : State -> { tags : List String, attributes : List String, schemes : List String }
getAll st =
    { tags = st.config.tags
    , attributes = st.config.attributes
    , schemes = st.config.allowedSchemes
    }


{-| Get the full whitelist configuration from the current state.

This includes allowed tags, allowed attributes, URL-like attributes, and allowed
URL schemes.
-}
getAllFull :
    State
    -> { tags : List String
       , attributes : List String
       , urlAttributes : List String
       , schemes : List String
       }
getAllFull st =
    { tags = st.config.tags
    , attributes = st.config.attributes
    , urlAttributes = st.config.urlAttributes
    , schemes = st.config.allowedSchemes
    }


{-| Get allowed URL schemes.

If whitelist mode is disabled, the default scheme list is returned.
-}
getAllowedSchemes : State -> List String
getAllowedSchemes st =
    if st.active then
        st.config.allowedSchemes

    else
        defaultConfig.allowedSchemes


{-| Create a whitelist from allowed tags and attributes.

The URL-like attributes default to `href` and `src`. The allowed URL schemes
default to `defaultConfig.allowedSchemes`.

    fromLists [ "p", "strong", "a" ] [ "href", "title" ]

-}
fromLists : List String -> List String -> Whitelist
fromLists tags attrs =
    normalize
        { tags = tags
        , attributes = attrs
        , urlAttributes = [ "href", "src" ]
        , allowedSchemes = defaultConfig.allowedSchemes
        }


{-| Create a whitelist from allowed tags, attributes, and URL schemes.

The URL-like attributes default to `href` and `src`.

    fromAll
        [ "p", "a" ]
        [ "href" ]
        [ "http:", "https:" ]

-}
fromAll : List String -> List String -> List String -> Whitelist
fromAll tags attrs schemes =
    normalize
        { tags = tags
        , attributes = attrs
        , urlAttributes = [ "href", "src" ]
        , allowedSchemes = schemes
        }


{-| Create a full whitelist configuration.

This variant allows configuring allowed tags, allowed attributes, URL-like
attributes, and allowed URL schemes explicitly.

    fromAllFull
        [ "p", "a", "img" ]
        [ "href", "src", "alt" ]
        [ "href", "src" ]
        [ "http:", "https:" ]

-}
fromAllFull :
    List String
    -> List String
    -> List String
    -> List String
    -> Whitelist
fromAllFull tags attrs urlAttrs schemes =
    normalize
        { tags = tags
        , attributes = attrs
        , urlAttributes = urlAttrs
        , allowedSchemes = schemes
        }


{-| Replace the allowed attributes in the current whitelist state.
-}
setAttributes : List String -> State -> State
setAttributes attrs st =
    let
        cfg =
            st.config
    in
    { st | config = normalize { cfg | attributes = attrs } }


{-| Replace the URL-like attributes in the current whitelist state.

URL-like attributes are checked against allowed URL schemes during
sanitization.
-}
setUrlAttributes : List String -> State -> State
setUrlAttributes urlAttrs st =
    let
        cfg =
            st.config
    in
    { st | config = normalize { cfg | urlAttributes = urlAttrs } }


{-| Replace the allowed URL schemes in the current whitelist state.

Schemes are normalized to lowercase and always end with `:`.
-}
setSchemes : List String -> State -> State
setSchemes schemes st =
    let
        cfg =
            st.config
    in
    { st | config = normalize { cfg | allowedSchemes = schemes } }


{-| Check whether a tag is allowed by the current whitelist configuration.
-}
isAllowedTag : State -> String -> Bool
isAllowedTag st tag =
    List.member (normName tag) st.config.tags


{-| Check whether an attribute is allowed by the current whitelist configuration.
-}
isAllowedAttribute : State -> String -> Bool
isAllowedAttribute st attr =
    List.member (normName attr) st.config.attributes


{-| Check whether an attribute should be treated as URL-like.

URL-like attributes are validated against the allowed URL schemes during
sanitization.
-}
isUrlAttribute : State -> String -> Bool
isUrlAttribute st attr =
    List.member (normName attr) st.config.urlAttributes


normalize : Whitelist -> Whitelist
normalize cfg =
    { tags =
        cfg.tags
            |> List.map normName
            |> List.filter (not << isBlockedTag)
            |> unique
    , attributes =
        cfg.attributes
            |> List.map normName
            |> List.filter (not << isBlockedAttribute)
            |> unique
    , urlAttributes =
        cfg.urlAttributes
            |> List.map normName
            |> List.filter (not << isBlockedAttribute)
            |> unique
    , allowedSchemes =
        cfg.allowedSchemes
            |> List.map toLowerScheme
            |> List.filter (not << isBlockedScheme)
            |> unique
    }


{-| Tags that are blocked regardless of whitelist configuration.

These tags are considered too risky to preserve in sanitized HTML.
-}
blockedTags : List String
blockedTags =
    [ "script", "style", "iframe", "object", "embed", "svg", "math" ]


{-| Attributes that are blocked regardless of whitelist configuration.

This includes style-related and document-embedding attributes. Inline event
handler attributes such as `onclick` and `onerror` are also blocked by
`isBlockedAttribute`.
-}
blockedAttributes : List String
blockedAttributes =
    [ "style", "srcdoc", "srcset", "xmlns" ]


{-| URL schemes that are blocked regardless of whitelist configuration.
-}
blockedSchemes : List String
blockedSchemes =
    [ "javascript:", "vbscript:", "livescript:", "mocha:" ]


{-| Check whether a tag is hard-blocked.
-}
isBlockedTag : String -> Bool
isBlockedTag tag =
    List.member (normName tag) blockedTags


{-| Check whether an attribute is hard-blocked.

This returns `True` for inline event handlers such as `onclick`, for attributes
listed in `blockedAttributes`, and for namespace declarations starting with
`xmlns`.
-}
isBlockedAttribute : String -> Bool
isBlockedAttribute attr =
    let
        normalized =
            normName attr
    in
    String.startsWith "on" normalized
        || List.member normalized blockedAttributes
        || String.startsWith "xmlns" normalized


{-| Check whether a URL scheme is hard-blocked.
-}
isBlockedScheme : String -> Bool
isBlockedScheme scheme =
    List.member (toLowerScheme scheme) blockedSchemes


normName : String -> String
normName s =
    s
        |> String.toLower
        |> String.trim
        |> String.filter (\c -> isAlphaNum c || c == '-')


toLowerScheme : String -> String
toLowerScheme s =
    let
        t =
            s
                |> String.toLower
                |> String.trim
    in
    if String.endsWith ":" t then
        t

    else
        t ++ ":"


unique : List String -> List String
unique xs =
    xs
        |> List.foldl
            (\x acc ->
                if List.member x acc then
                    acc

                else
                    x :: acc
            )
            []
        |> List.reverse