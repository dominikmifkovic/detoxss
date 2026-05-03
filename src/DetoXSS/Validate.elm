module DetoXSS.Validate exposing
    ( ValidationError(..)
    , Rule
    , validate
    , validateEmail
    , validatePhone
    , validateUsername
    , validatePassword
    , nonEmpty
    , minLength
    , maxLength
    , allowedChars
    , matchesRegex
    )

{-| General validation helpers for form input.

This module validates whether a value follows application-level rules such as
being non-empty, having a specific length, matching a regular expression, or
looking like an email address.

Validation is not the same as XSS protection. A valid value may still need
sanitization or AST analysis before it is used in an output context.

@docs ValidationError, Rule

@docs validate

@docs validateEmail, validatePhone, validateUsername, validatePassword

@docs nonEmpty, minLength, maxLength

@docs allowedChars, matchesRegex

-}

import DetoXSS.Core exposing (ValidatedInput, fromValidated)
import Regex exposing (Regex)


type ValidationError
    = Empty
    | TooShort Int
    | TooLong Int
    | InvalidEmail
    | InvalidPhone
    | InvalidChars String
    | WeakPassword String
    | Custom String


type alias Rule =
    String -> List ValidationError


validate : List Rule -> String -> Result (List ValidationError) ValidatedInput
validate rules raw =
    let
        cleaned =
            String.trim raw

        errors =
            rules
                |> List.concatMap (\rule -> rule cleaned)
    in
    if List.isEmpty errors then
        Ok (fromValidated cleaned)

    else
        Err errors


nonEmpty : Rule
nonEmpty s =
    if String.isEmpty (String.trim s) then
        [ Empty ]

    else
        []


minLength : Int -> Rule
minLength n s =
    if String.length s < n then
        [ TooShort n ]

    else
        []


maxLength : Int -> Rule
maxLength n s =
    if String.length s > n then
        [ TooLong n ]

    else
        []


allowedChars : Regex -> String -> Rule
allowedChars rx description =
    \s ->
        if Regex.contains rx s then
            []

        else
            [ InvalidChars description ]


matchesRegex : Regex -> ValidationError -> Rule
matchesRegex rx err =
    \s ->
        if Regex.contains rx s then
            []

        else
            [ err ]


validateEmail : String -> Result (List ValidationError) ValidatedInput
validateEmail s =
    let
        emailRx =
            unsafeRegex "^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$"
    in
    validate
        [ nonEmpty
        , matchesRegex emailRx InvalidEmail
        ]
        s


validatePhone : String -> Result (List ValidationError) ValidatedInput
validatePhone s =
    let
        phoneRx =
            unsafeRegex "^[0-9\\+\\-\\s\\(\\)]+$"

        enoughDigits str =
            let
                digitsCount =
                    str
                        |> String.toList
                        |> List.filter Char.isDigit
                        |> List.length
            in
            if digitsCount < 7 then
                [ InvalidPhone ]

            else
                []
    in
    validate
        [ nonEmpty
        , matchesRegex phoneRx InvalidPhone
        , enoughDigits
        ]
        s


validateUsername : String -> Result (List ValidationError) ValidatedInput
validateUsername s =
    let
        usernameRx =
            unsafeRegex "^[A-Za-z0-9_.-]+$"
    in
    validate
        [ nonEmpty
        , minLength 3
        , maxLength 32
        , allowedChars usernameRx "povolené sú len písmená, čísla a znaky _.-"
        ]
        s


validatePassword : String -> Result (List ValidationError) ValidatedInput
validatePassword s =
    let
        hasUpper =
            unsafeRegex "[A-Z]"

        hasLower =
            unsafeRegex "[a-z]"

        hasDigit =
            unsafeRegex "[0-9]"

        hasSpecial =
            unsafeRegex "[^A-Za-z0-9]"

        passwordStrengthRule str =
            let
                problems =
                    []
                        |> addIfMissing (Regex.contains hasUpper str) "aspoň jedno veľké písmeno"
                        |> addIfMissing (Regex.contains hasLower str) "aspoň jedno malé písmeno"
                        |> addIfMissing (Regex.contains hasDigit str) "aspoň jednu číslicu"
                        |> addIfMissing (Regex.contains hasSpecial str) "aspoň jeden špeciálny znak"
            in
            case List.reverse problems of
                [] ->
                    []

                missing ->
                    [ WeakPassword (String.join ", " missing) ]
    in
    validate
        [ nonEmpty
        , minLength 8
        , passwordStrengthRule
        ]
        s


unsafeRegex : String -> Regex
unsafeRegex pattern =
    Regex.fromString pattern
        |> Maybe.withDefault Regex.never


addIfMissing : Bool -> String -> List String -> List String
addIfMissing present message acc =
    if present then
        acc

    else
        message :: acc