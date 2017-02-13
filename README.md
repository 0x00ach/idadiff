# idadiff
IDAPython script in order to auto-rename sub.

The script uses the @Heurs MACHOC algorithm (https://github.com/ANSSI-FR/polichombr) in order to build tiny CFG hashes of a source binary sample in IDA PRO. These hashes may be compared against the ones in the destination binary sample. If a 1-1 relationship is found, the  sub is renamed.

TODO:
- code cleaning;
- N grams (3 and 5);
- use a %temp% or /tmp file to share the hashes;
- other methods.
