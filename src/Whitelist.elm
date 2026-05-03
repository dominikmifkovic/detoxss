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

import Char exposing (isAlphaNum)


type alias Whitelist =
    { tags : List String
    , attributes : List String
    , urlAttributes : List String
    , allowedSchemes : List String
    }


type alias State =
    { active : Bool
    , config : Whitelist
    }


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


initialState : State
initialState =
    { active = False
    , config = defaultConfig
    }


enable : State -> State
enable st =
    { st | active = True }


disable : State -> State
disable st =
    { st | active = False }


isEnabled : State -> Bool
isEnabled st =
    st.active


set : Whitelist -> State -> State
set cfg st =
    { st | config = normalize cfg }


get : State -> { tags : List String, attributes : List String }
get st =
    { tags = st.config.tags
    , attributes = st.config.attributes
    }


getAll : State -> { tags : List String, attributes : List String, schemes : List String }
getAll st =
    { tags = st.config.tags
    , attributes = st.config.attributes
    , schemes = st.config.allowedSchemes
    }


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


getAllowedSchemes : State -> List String
getAllowedSchemes st =
    if st.active then
        st.config.allowedSchemes

    else
        defaultConfig.allowedSchemes


fromLists : List String -> List String -> Whitelist
fromLists tags attrs =
    normalize
        { tags = tags
        , attributes = attrs
        , urlAttributes = [ "href", "src" ]
        , allowedSchemes = defaultConfig.allowedSchemes
        }


fromAll : List String -> List String -> List String -> Whitelist
fromAll tags attrs schemes =
    normalize
        { tags = tags
        , attributes = attrs
        , urlAttributes = [ "href", "src" ]
        , allowedSchemes = schemes
        }


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


setAttributes : List String -> State -> State
setAttributes attrs st =
    let
        cfg =
            st.config
    in
    { st | config = normalize { cfg | attributes = attrs } }


setUrlAttributes : List String -> State -> State
setUrlAttributes urlAttrs st =
    let
        cfg =
            st.config
    in
    { st | config = normalize { cfg | urlAttributes = urlAttrs } }


setSchemes : List String -> State -> State
setSchemes schemes st =
    let
        cfg =
            st.config
    in
    { st | config = normalize { cfg | allowedSchemes = schemes } }


isAllowedTag : State -> String -> Bool
isAllowedTag st tag =
    List.member (normName tag) st.config.tags


isAllowedAttribute : State -> String -> Bool
isAllowedAttribute st attr =
    List.member (normName attr) st.config.attributes


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


blockedTags : List String
blockedTags =
    [ "script", "style", "iframe", "object", "embed", "svg", "math" ]


blockedAttributes : List String
blockedAttributes =
    [ "style", "srcdoc", "srcset", "xmlns" ]


blockedSchemes : List String
blockedSchemes =
    [ "javascript:", "vbscript:", "livescript:", "mocha:" ]


isBlockedTag : String -> Bool
isBlockedTag tag =
    List.member (normName tag) blockedTags


isBlockedAttribute : String -> Bool
isBlockedAttribute attr =
    let
        normalized =
            normName attr
    in
    String.startsWith "on" normalized
        || List.member normalized blockedAttributes
        || String.startsWith "xmlns" normalized


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