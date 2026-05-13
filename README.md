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
- Analyzer usage counter in the summary bar
- Double-click history entries to copy them
- Configurable generator batch size
- Copy Batch Summary action for generated candidates

### Analyzer tab

- Score and strength update as you type.
- The checks table shows length, character variety, entropy, and common-password status.
- Recent analyses are stored as masked history entries.
- A copy button captures the latest summary, including the HIBP result.
- The summary bar also shows how many analyses have been run.
- Double-click a history entry to copy it back to the clipboard.

### Generator tab

- Choose password length and the character sets to include.
- Set the batch size for each generation run.
- Optionally avoid ambiguous characters like `0`, `O`, `1`, `l`, and `I`.
- Generate five candidates at a time and inspect their strength scores.
- Auto-selects the strongest generated candidate and shows a batch summary with average score.
- Copy the selected candidate or the strongest candidate directly to the clipboard.
- Copy the batch summary as a quick status line.

## Usage

1. Open the Analyzer tab and type a password to review its score, recommendations, and HIBP status.
2. Use the Copy Summary button to grab a quick shareable result for the latest check.
3. Switch to the Generator tab to create new passwords with the options you want.
4. Copy a generated password, or send it back to the Analyzer tab for a full check.

Keyboard support:

- `Enter` runs the active tab action.
- `Esc` clears the analyzer screen.

## Notes

- The app depends on the HIBP Pwned Passwords API for breach checks.
- The Generator tab relies on the built-in password generator module.
- Generated candidates are scored locally using the same analyzer logic as the main screen.
