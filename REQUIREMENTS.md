# Assignment 1 (group of four)

Design and build a web application for a **specific scenario of your own choosing**.

* Pick a concrete real-world setting where protecting stored user data matters. Decide who the users are, what they store, and why it needs protecting.
* A generic "file encryption service" is **not** a scenario and will not be accepted. Your application must clearly make sense for the setting you chose.
* Your application must handle personal data, scanned identity documents, office documents, and video.
* Decide which data counts as private, and base that decision on the relevant data protection regulations (GDPR / UU PDP).
* Everything you store must be protected with each of the following ciphers: **AES, DES, RC4**.
* Only an authenticated user may get their own data back, and it must come back intact.

## Technical requirements

* Choose an appropriate mode of operation for each block cipher. **ECB is not acceptable.**
* You may use any language and cryptography library you like.
* Evaluate how the three ciphers compare in practice. Decide what to measure, how to measure it reliably, and what the results tell you for your scenario. Do not present numbers without interpreting them.

## Report (maximum 2 A4 pages)

* Your scenario, and why this application is useful in it.
* The analysis you chose to perform, and why it is the right one for your scenario.
* A justification for every significant design decision (architecture, mode choices, key handling, storage, etc.). "It was the easiest option" is not a justification.

## Submission and marking

* Push **all code to GitHub**. Your commit history will be used for marking, so commit regularly and meaningfully.
* Share your AI conversations: include a **link** to the conversation and a **screenshot** of it in your submission. If you used AI, we need to see how.
* Marks are given for correctness and for the quality of your reasoning.
* Plagiarism, including unverified AI-generated content, will receive 0.