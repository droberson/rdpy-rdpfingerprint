# rdpy-fingerprint.py
Quick and dirty script that remotely fingerprints an operating system based
on the contents of the login screen presented by RDP (Remote Desktop Protocol).

## Dependencies
- rdpy: apt install rdpy
- ssdeep: apt install python-ssdeep

## Why?
I couldn't find any tools that would take in a list of hosts or a range of IP
addresses, connect to RDP, and tell me what OS it is. Connecting to more than
a handful manually and recording what is presented by hand is tedious work and
unbecoming of a modern IT professional.

Additionally, I did not have access to most of these machines to use something
more suitable to this task such as WMIC.

After about an hour of looking for suitable tools and libraries to accomplish
this task, I ended up taking the path of least resistance and modifying the
rdpy-rdpscreenshot.py script that is included with rdpy to ssdeep hash the
file containing the screen shot, then compare it to a dictionary of hash :
known operating system. Whichever hash out of the known list scores highest is
likely to be what is running on the machine.

This tool is not perfect. Slower machines may take a while for RDP to display
data, resulting in a screen capture of a black or Windows blue screen. If you
get unknown results, try again or increasing the timeout using the -t flag. I
also encountered a few RDP configurations that caused the original script to
throw exceptions or to enter an intinite loop. I have not gotten around to
troubleshooting this yet. Additionally, if the machine's administrator has
changed the background, added some corporate logo, a warning banner, or a
number of other things, this will not work accurately with the current hash
database.

I realize that this is code is far from complete, but several people have
expressed interest, so I'm releasing this as-is for now.

## TODO
- More signatures.

- General code cleanup and better error handling.

- Output in a more intelligent manner so this can be integrated into scripts
  easier.

- Maybe saving the screenshot in a different format will increase accuracy?

- Store the hashes in a more intelligent manner.

- Maybe use a different algorithm besides ssdeep? I know other piecewise
  hashing algorithms exist. Maybe another comparison approach altogether?

- Chop the screenshots into pieces where the banners typically reside and hash
  that instead of the entire screen? This would avoid the issue of users being
  logged in, artwork, loading screens, mouse cursors, and so on being present
  on the screen.

- Read the protocol data itself versus taking a screenshot? I didn't look too
  far into the RDP protocol beyond reading API documentation for FreeRDP and
  rdpy and looking at a couple of packet captures of RDP connections.

