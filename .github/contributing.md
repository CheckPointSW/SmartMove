## Code and testing requirements:
 - The tool is developed using Microsoft C# language and .NET framework version 4.5 (WPF application).
 - The project solution file is configured for Microsoft Visual Studio 2012 (C# v5).
 - Do not add new external libraries or any 3rd party code (open source or commercial).
 - The code will be implemented with high quality standards. It should be designed well, refactored for easy reuse and easy maintenance, efficient as possible, readable and well documented.
 - Verify functionality and correctness of the tool, including end-to-end testing & QA.

## Committing code to GitHub:
 - Commit/PR name needs to be meaningful and explain the change and not the issue it solves. For example: User is suffering from failure   due to host name collision – commit name would be: “Handle host creation in case of name duplications”.
 - Commit/PR description needs to contain more details about the issue and the solution.
   For example: for the same scenario above, commit description would be: “Before adding new host the program will check if host exists and will add ‘_duplicated’ as suffix to the name”.
