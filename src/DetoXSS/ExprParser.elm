module DetoXSS.ExprParser exposing
    ( parseExpression
    , Parsed(..)
    , HtmlNode(..)
    , HtmlAttribute
    , Position
    )

import Char
import Parser exposing (..)
import Set


type Parsed
    = Ok (List HtmlNode)
    | Err String


type HtmlNode
    = Element { tag : String, attributes : List HtmlAttribute, children : List HtmlNode, position : Position }
    | Text { content : String, position : Position }
    | Comment { content : String, position : Position }


type alias HtmlAttribute =
    { name : String, value : String, position : Position }


type alias Position =
    { row : Int, col : Int }


parseExpression : String -> Parsed
parseExpression src =
    parseWith htmlDocument src


parseExpressionStrict : String -> Parsed
parseExpressionStrict src =
    parseWith htmlDocumentStrict src


parseWith : Parser (List HtmlNode) -> String -> Parsed
parseWith parser src =
    let
        prepared =
            src
                |> stripNullBytesForParser
    in
    case run parser prepared of
        Result.Ok nodes ->
            Ok nodes

        Result.Err deadEnds ->
            Err (deadEndsToString deadEnds)

stripNullBytesForParser : String -> String
stripNullBytesForParser src =
    src
        |> String.replace "\u{0000}" ""
        |> String.replace "\u{200B}" ""
        |> String.replace "\u{200C}" ""
        |> String.replace "\u{200D}" ""
        |> String.replace "\u{FEFF}" ""


stripNullBytes : String -> String
stripNullBytes src =
    src
        |> String.replace "\u{0000}" ""
        |> String.replace "\\x0" ""
        |> String.replace "\\x00" ""
        |> String.replace "\u{200B}" ""
        |> String.replace "\u{200C}" ""
        |> String.replace "\u{200D}" ""
        |> String.replace "\u{FEFF}" ""


stripQuotes : String -> String
stripQuotes src =
    src
        |> String.replace "\"" ""
        |> String.replace "'" ""

decodeNamedEntities : String -> String
decodeNamedEntities src =
    src
        |> String.replace "&lt;" "<"
        |> String.replace "&gt;" ">"
        |> String.replace "&amp;" "&"
        |> String.replace "&quot;" "\""
        |> String.replace "&#39;" "'"
        |> String.replace "&sol;" "/"
        |> String.replace "&colon;" ":"

decodeHtmlNumericEntities : String -> String
decodeHtmlNumericEntities src =
    decodeEntitiesHelp (String.toList src) []


decodeEntitiesHelp : List Char -> List Char -> String
decodeEntitiesHelp remaining acc =
    case remaining of
        [] ->
            String.fromList (List.reverse acc)

        '&' :: '#' :: 'x' :: rest ->
            let
                ( hexChars, after ) =
                    collectUntilSemicolon rest []
            in
            if List.isEmpty hexChars then
                decodeEntitiesHelp rest (List.reverse (String.toList "&#x") ++ acc)
            else
                case hexToInt (String.fromList hexChars) of
                    Just code ->
                        decodeEntitiesHelp after (Char.fromCode code :: acc)
                    Nothing ->
                        decodeEntitiesHelp rest (List.reverse (String.toList "&#x") ++ acc)

        '&' :: '#' :: rest ->
            let
                ( decChars, after ) =
                    collectUntilSemicolon rest []
            in
            if List.isEmpty decChars then
                decodeEntitiesHelp rest (List.reverse (String.toList "&#") ++ acc)
            else
                case String.toInt (String.fromList decChars) of
                    Just code ->
                        decodeEntitiesHelp after (Char.fromCode code :: acc)
                    Nothing ->
                        decodeEntitiesHelp rest (List.reverse (String.toList "&#") ++ acc)

        c :: rest ->
            decodeEntitiesHelp rest (c :: acc)


collectUntilSemicolon : List Char -> List Char -> ( List Char, List Char )
collectUntilSemicolon remaining acc =
    case remaining of
        [] ->
            ( List.reverse acc, [] )
        ';' :: rest ->
            ( List.reverse acc, rest )
        c :: rest ->
            if Char.isAlphaNum c then
                collectUntilSemicolon rest (c :: acc)
            else
                ( List.reverse acc, c :: rest )


decodeUnicodeEscapes : String -> String
decodeUnicodeEscapes src =
    decodeUnicodeHelp (String.toList src) []


decodeUnicodeHelp : List Char -> List Char -> String
decodeUnicodeHelp remaining acc =
    case remaining of
        [] ->
            String.fromList (List.reverse acc)
        '\\' :: 'u' :: h1 :: h2 :: h3 :: h4 :: rest ->
            case hexToInt (String.fromList [ h1, h2, h3, h4 ]) of
                Just code ->
                    decodeUnicodeHelp rest (Char.fromCode code :: acc)
                Nothing ->
                    decodeUnicodeHelp (h1 :: h2 :: h3 :: h4 :: rest) ('u' :: '\\' :: acc)
        c :: rest ->
            decodeUnicodeHelp rest (c :: acc)


decodeHexEscapes : String -> String
decodeHexEscapes src =
    decodeHexHelp (String.toList src) []


decodeHexHelp : List Char -> List Char -> String
decodeHexHelp remaining acc =
    case remaining of
        [] ->
            String.fromList (List.reverse acc)
        '\\' :: 'x' :: h1 :: h2 :: rest ->
            case hexToInt (String.fromList [ h1, h2 ]) of
                Just code ->
                    decodeHexHelp rest (Char.fromCode code :: acc)
                Nothing ->
                    decodeHexHelp (h1 :: h2 :: rest) ('x' :: '\\' :: acc)
        c :: rest ->
            decodeHexHelp rest (c :: acc)


decodeUrlEncodedChars : String -> String
decodeUrlEncodedChars src =
    decodeUrlHelp (String.toList src) []


decodeUrlHelp : List Char -> List Char -> String
decodeUrlHelp remaining acc =
    case remaining of
        [] ->
            String.fromList (List.reverse acc)
        '%' :: h1 :: h2 :: rest ->
            case hexToInt (String.fromList [ h1, h2 ]) of
                Just code ->
                    if (code >= 0x20 && code <= 0x7E) || code == 0x09 || code == 0x0A || code == 0x0D then
                        decodeUrlHelp rest (Char.fromCode code :: acc)
                    else
                        decodeUrlHelp (h1 :: h2 :: rest) acc
                Nothing ->
                    decodeUrlHelp (h1 :: h2 :: rest) acc
        c :: rest ->
            decodeUrlHelp rest (c :: acc)


hexToInt : String -> Maybe Int
hexToInt s =
    case
        List.foldr
            (\c acc ->
                case acc of
                    Nothing -> Nothing
                    Just ( result, mult ) ->
                        case hexCharToInt c of
                            Just d  -> Just ( result + d * mult, mult * 16 )
                            Nothing -> Nothing
            )
            (Just ( 0, 1 ))
            (String.toList (String.toLower s))
    of
        Just ( result, _ ) -> Just result
        Nothing            -> Nothing


hexCharToInt : Char -> Maybe Int
hexCharToInt c =
    if c >= '0' && c <= '9' then
        Just (Char.toCode c - Char.toCode '0')
    else if c >= 'a' && c <= 'f' then
        Just (Char.toCode c - Char.toCode 'a' + 10)
    else
        Nothing


deadEndsToString : List DeadEnd -> String
deadEndsToString errs =
    errs
        |> List.map (\e -> "Line " ++ String.fromInt e.row ++ ", Col " ++ String.fromInt e.col ++ ": " ++ problemToString e.problem)
        |> String.join "\n"


problemToString : Problem -> String
problemToString problem =
    case problem of
        Expecting str        -> "Expecting " ++ str
        ExpectingInt         -> "Expecting int"
        ExpectingHex         -> "Expecting hex"
        ExpectingOctal       -> "Expecting octal"
        ExpectingBinary      -> "Expecting binary"
        ExpectingFloat       -> "Expecting float"
        ExpectingNumber      -> "Expecting number"
        ExpectingVariable    -> "Expecting variable"
        ExpectingSymbol str  -> "Expecting symbol " ++ str
        ExpectingKeyword str -> "Expecting keyword " ++ str
        ExpectingEnd         -> "Expecting end"
        UnexpectedChar       -> "Unexpected char"
        Problem str          -> str
        BadRepeat            -> "Bad repeat"




htmlDocumentStrict : Parser (List HtmlNode)
htmlDocumentStrict =
    htmlDocument
        |. spaces
        |. end


htmlDocument : Parser (List HtmlNode)
htmlDocument =
    loop [] htmlNodesHelp


htmlNodesHelp : List HtmlNode -> Parser (Step (List HtmlNode) (List HtmlNode))
htmlNodesHelp nodes =
    oneOf
        [ succeed (\node -> Loop (node :: nodes)) |= htmlNode
        , succeed (Done (List.reverse nodes))
        ]


htmlNode : Parser HtmlNode
htmlNode =
    succeed identity
        |. spaces
        |= oneOf
            [ backtrackable (lazy (\_ -> comment))
            , backtrackable (lazy (\_ -> processingInstruction))
            , backtrackable (lazy (\_ -> cdata))
            , backtrackable (lazy (\_ -> closingTagSkip))
            , backtrackable (lazy (\_ -> element))
            , backtrackable (lazy (\_ -> malformedTag))
            , lazy (\_ -> textNode)
            ]
        |. spaces

malformedTag : Parser HtmlNode
malformedTag =
    getPosition
        |> andThen
            (\pos ->
                getChompedString
                    (succeed ()
                        |. symbol "<"
                        |. chompWhile (\c -> c /= '>')
                        |. oneOf [ symbol ">", end ]
                    )
                    |> map (\content -> Text { content = content, position = posToRecord pos })
            )

closingTagSkip : Parser HtmlNode
closingTagSkip =
    getPosition
        |> andThen
            (\pos ->
                getChompedString
                    (succeed ()
                        |. symbol "</"
                        |. chompWhile (\c -> c /= '>')
                        |. oneOf [ symbol ">", succeed () ]
                    )
                    |> map (\content -> Text { content = content, position = posToRecord pos })
            )


processingInstruction : Parser HtmlNode
processingInstruction =
    getPosition
        |> andThen
            (\pos ->
                getChompedString
                    (succeed ()
                        |. symbol "<?"
                        |. chompWhile (\c -> c /= '>')
                        |. oneOf [ symbol ">", succeed () ]
                    )
                    |> map (\content -> Text { content = content, position = posToRecord pos })
            )


cdata : Parser HtmlNode
cdata =
    getPosition
        |> andThen
            (\pos ->
                succeed (\content -> Text { content = content, position = posToRecord pos })
                    |. symbol "<![CDATA["
                    |= getChompedString (chompUntil "]]>")
                    |. symbol "]]>"
            )


element : Parser HtmlNode
element =
    getPosition
        |> andThen
            (\startPos ->
                succeed identity
                    |. symbol "<"
                    |= tagName
                    |> andThen
                        (\tag ->
                            attributes
                                |> andThen (parseElementEnd startPos tag)
                        )
            )


parseElementEnd : ( Int, Int ) -> String -> List HtmlAttribute -> Parser HtmlNode
parseElementEnd startPos tag attrs =
    oneOf
        [ succeed
            (Element
                { tag = tag
                , attributes = attrs
                , children = []
                , position = posToRecord startPos
                }
            )
            |. spaces
            |. symbol "/>"

        , if isSelfClosing tag then
            succeed
                (Element
                    { tag = tag
                    , attributes = attrs
                    , children = []
                    , position = posToRecord startPos
                    }
                )
                |. spaces
                |. oneOf
                    [ symbol ">"
                    , end
                    ]
          else
            succeed
                (\kids ->
                    Element
                        { tag = tag
                        , attributes = attrs
                        , children = kids
                        , position = posToRecord startPos
                        }
                )
                |. spaces
                |. symbol ">"
                |= children tag

        , succeed
            (Element
                { tag = tag
                , attributes = attrs
                , children = []
                , position = posToRecord startPos
                }
            )
            |. spaces
            |. end
        ]

isSelfClosing : String -> Bool
isSelfClosing tag =
    List.member tag
        [ "area", "base", "br", "col", "embed", "hr", "img", "image"
        , "input", "link", "meta", "param", "source", "track", "wbr"
        , "frame", "isindex", "keygen", "command"
        ]


children : String -> Parser (List HtmlNode)
children tagToClose =
    loop [] (childrenHelp tagToClose)


childrenHelp : String -> List HtmlNode -> Parser (Step (List HtmlNode) (List HtmlNode))
childrenHelp tagToClose nodes =
    oneOf
        [ backtrackable (succeed (Done (List.reverse nodes)) |. closingTag tagToClose)
        , succeed (\node -> Loop (node :: nodes)) |= htmlNode
        , succeed (Done (List.reverse nodes))
        ]


closingTag : String -> Parser ()
closingTag expectedTag =
    succeed ()
        |. symbol "</"
        |. spaces
        |. closingTagName expectedTag
        |. spaces
        |. chompWhile (\c -> c /= '>')
        |. oneOf [ symbol ">", succeed () ]


closingTagName : String -> Parser ()
closingTagName expectedTag =
    variable
        { start = Char.isAlpha
        , inner = \c -> Char.isAlphaNum c || c == '-' || c == '_'
        , reserved = Set.empty
        }
        |> andThen
            (\actual ->
                if String.toLower actual == expectedTag then
                    succeed ()
                else
                    problem ("Mismatched closing tag: expected " ++ expectedTag ++ " but found " ++ actual)
            )


tagName : Parser String
tagName =
    variable
        { start = \c -> Char.isAlpha c || c == '_'
        , inner = \c -> Char.isAlphaNum c || c == '-' || c == '_' || c == ':' || c == '.'
        , reserved = Set.empty
        }
        |> map String.toLower




attributes : Parser (List HtmlAttribute)
attributes =
    loop [] attributesHelp


attributesHelp : List HtmlAttribute -> Parser (Step (List HtmlAttribute) (List HtmlAttribute))
attributesHelp attrs =
    oneOf
        [ backtrackable (succeed (\attr -> Loop (attr :: attrs)) |. spaces |= attribute)
        , succeed (Done (List.reverse attrs))
        ]


attribute : Parser HtmlAttribute
attribute =
    getPosition
        |> andThen
            (\startPos ->
                attributeName
                    |> andThen
                        (\name ->
                            oneOf
                                [ backtrackable
                                    (succeed (\value -> { name = name, value = value, position = posToRecord startPos })
                                        |. spaces
                                        |. symbol "="
                                        |. spaces
                                        |= attributeValue
                                    )
                                , succeed { name = name, value = "", position = posToRecord startPos }
                                ]
                        )
            )


attributeName : Parser String
attributeName =
    variable
        { start = \c -> Char.isAlpha c || c == '_' || c == '-' || c == ':' || c == '@'
        , inner = \c -> Char.isAlphaNum c || c == '-' || c == '_' || c == ':' || c == '.' || c == '@'
        , reserved = Set.empty
        }
        |> map String.toLower


attributeValue : Parser String
attributeValue =
    oneOf
        [ quotedValue '"'
        , quotedValue '\''
        , backtickValue
        , unquotedValue
        ]


quotedValue : Char -> Parser String
quotedValue quote =
    succeed identity
        |. symbol (String.fromChar quote)
        |= (getOffset
                |> andThen
                    (\startOffset ->
                        getSource
                            |> andThen
                                (\src ->
                                    let
                                        remaining = String.dropLeft startOffset src
                                        ( value, consumeCount ) = scanQuotedValue quote (String.toList remaining) []
                                    in
                                    succeed value
                                        |. chompExactly consumeCount
                                )
                    )
           )


chompExactly : Int -> Parser ()
chompExactly n =
    if n <= 0 then
        succeed ()
    else
        chompIf (\_ -> True)
            |> andThen (\_ -> chompExactly (n - 1))


scanQuotedValue : Char -> List Char -> List Char -> ( String, Int )
scanQuotedValue quote remaining acc =
    scanQuotedValueHelp quote remaining acc 0


scanQuotedValueHelp : Char -> List Char -> List Char -> Int -> ( String, Int )
scanQuotedValueHelp quote remaining acc consumed =
    case remaining of
        [] ->
            ( String.fromList (List.reverse acc), consumed )

        c :: rest ->
            if c == quote then
                case rest of
                    [] ->
                        ( String.fromList (List.reverse acc), consumed + 1 )

                    next :: _ ->
                        if isSpaceChar next || next == '>' || next == '/' then
                            ( String.fromList (List.reverse acc), consumed + 1 )

                        else
                            scanQuotedValueHelp quote rest (c :: acc) (consumed + 1)

            else
                scanQuotedValueHelp quote rest (c :: acc) (consumed + 1)


isSpaceChar : Char -> Bool
isSpaceChar c =
    c == ' '
        || c == '\t'
        || c == '\n'
        || c == '\r'
        || c == '\u{000B}' -- vertical tab
        || c == '\u{000C}' -- form feed


backtickValue : Parser String
backtickValue =
    succeed identity
        |. symbol "`"
        |= getChompedString (chompWhile (\c -> c /= '`'))
        |. oneOf [ symbol "`", succeed () ]


unquotedValue : Parser String
unquotedValue =
    getChompedString
        (chompIf (\c -> not (isSpaceChar c) && c /= '>' && c /= '"' && c /= '\'' && c /= '`')
            |. chompWhile (\c -> not (isSpaceChar c) && c /= '>')
        )


textNode : Parser HtmlNode
textNode =
    getPosition
        |> andThen
            (\pos ->
                getChompedString
                    (chompIf (\c -> c /= '<')
                        |. chompWhile (\c -> c /= '<')
                    )
                    |> map (\content -> Text { content = content, position = posToRecord pos })
            )


comment : Parser HtmlNode
comment =
    getPosition
        |> andThen
            (\pos ->
                succeed (\content -> Comment { content = content, position = posToRecord pos })
                    |. symbol "<!--"
                    |= getChompedString (chompUntil "-->")
                    |. symbol "-->"
            )


isSpace : Char -> Bool
isSpace c =
    isSpaceChar c


spaces : Parser ()
spaces =
    chompWhile isSpaceChar


posToRecord : ( Int, Int ) -> Position
posToRecord ( row, col ) =
    { row = row, col = col }


getPosition : Parser ( Int, Int )
getPosition =
    succeed Tuple.pair
        |= getRow
        |= getCol
