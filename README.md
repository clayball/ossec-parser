# OSSEC Alert Parser

Parse OSSEC alert log files. Save output a useful format for processing.

## Alert Fields

- All alerts start with '** Alert'.
- All alerts have a minimum of four lines. 
- Composite alerts will have multiple Log Information fields.
- The fields inside brakets don't appear in every alert. These are also indented by one space.

A typical alert..

** Alert timestamp: - group,group,
YYYY Mon DD 00:00:00 (hostname) XXX.XXX.XXX.XXX->/log/file
Rule: XXXXXX (level X) -> 'Alert Description.'
 [Src IP: XXX.XXX.XXX.XXX]
 [User: user]
Log Information
 [Log Information]

## Example Usage

TODO:
