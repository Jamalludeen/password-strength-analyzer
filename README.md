# Password Strength Analyzer

A python GUI application for analyzing password strengths.

This Application is checking whether a password has appeared in known data breaches, using the Have I Been Pwned (HIBP) Pwned Passwords API.

## Overview

The app now uses a tabbed layout to keep the interface focused:

- The Analyzer tab checks password strength, entropy, common password usage, and HIBP breach status.
- The Generator tab creates password candidates with configurable rules and quick actions.

## Features

- Live strength scoring while typing
- HIBP breach lookup with a background request indicator
- Recent analysis history with masked passwords
- Copyable analysis summary for quick sharing
- Dedicated Generator tab with configurable password options
- One-click actions to copy or analyze generated candidates
- Batch summary showing average score and the strongest generated password
- Copy Strongest action for the current generator batch

### Analyzer tab

- Score and strength update as you type.
- The checks table shows length, character variety, entropy, and common-password status.
- Recent analyses are stored as masked history entries.
- A copy button captures the latest summary, including the HIBP result.

### Generator tab

- Choose password length and the character sets to include.
- Optionally avoid ambiguous characters like `0`, `O`, `1`, `l`, and `I`.
- Generate five candidates at a time and inspect their strength scores.
- Auto-selects the strongest generated candidate and shows a batch summary with average score.
- Copy the selected candidate or the strongest candidate directly to the clipboard.
