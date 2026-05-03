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

{-| Possible validation errors returned by the validation helpers.

These errors describe why a value did not pass a validation rule.
-}
type ValidationError
    = Empty
    | TooShort Int
    | TooLong Int
    | InvalidEmail
    | InvalidPhone
    | InvalidChars String
    | WeakPassword String
    | Custom String

{-| Validation rule.

A rule receives a string and returns a list of validation errors. An empty list
means that the value passed that rule.
-}
type alias Rule =
    String -> List ValidationError

{-| Run a list of validation rules against a string.

The input is trimmed before validation. If all rules pass, the cleaned value is
returned as `ValidatedInput`.
-}
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

{-| Require a non-empty value.
-}
nonEmpty : Rule
nonEmpty s =
    if String.isEmpty (String.trim s) then
        [ Empty ]

    else
        []


{-| Require a minimum string length.
-}
minLength : Int -> Rule
minLength n s =
    if String.length s < n then
        [ TooShort n ]

    else
        []


{-| Require a maximum string length.
-}
maxLength : Int -> Rule
maxLength n s =
    if String.length s > n then
        [ TooLong n ]

    else
        []


{-| Require the value to match a regular expression.

The description is used in the `InvalidChars` error when the value does not
match.
-}
allowedChars : Regex -> String -> Rule
allowedChars rx description =
    \s ->
        if Regex.contains rx s then
            []

        else
            [ InvalidChars description ]


{-| Create a validation rule from a regular expression and custom error.
-}
matchesRegex : Regex -> ValidationError -> Rule
matchesRegex rx err =
    \s ->
        if Regex.contains rx s then
            []

        else
            [ err ]


{-| Validate a simple email address.

This checks the general shape of an email address. It does not verify whether
the address actually exists.
-}
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


{-| Validate a phone-like value.

The value may contain digits, spaces, plus signs, dashes, and parentheses.
-}
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


{-| Validate a username.

The username must be non-empty, have an allowed length, and contain only
letters, digits, underscores, dots, or dashes.
-}
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
        , allowedChars usernameRx "only letters, numbers and characters _.- are allowed"
        ]
        s


{-| Validate a password.

The password must be non-empty, have a minimum length, and contain a mixture of
character classes.
-}
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
                        |> addIfMissing (Regex.contains hasUpper str) "at least one uppercase letter"
                        |> addIfMissing (Regex.contains hasLower str) "at least one lowercase letter"
                        |> addIfMissing (Regex.contains hasDigit str) "at least one digit"
                        |> addIfMissing (Regex.contains hasSpecial str) "at least one special character"
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