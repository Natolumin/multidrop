# SAPDump

sapdump is a tool to dump SAP announcements to the console, to find missing channels or channel parameters.

## Usage

```
Usage of sapdump:
  -4	Only listen on ipv4 groups (overriden by -group)
  -6	Only listen on ipv6 groups (overriden by -group)
  -curses
        Display continuous stats in a table instead of dumping announcements ("saptop" mode)
  -format string
    	Format string following text/template for dumping SAP announcements (default "{{.Description}}\n\n")
  -group string
    	Comma-separated Group(s) on which to listen for SAP announcements.
```
