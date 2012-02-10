#1. Name
anapickle - Toolset for writing shellcode in Python's Pickle language and for manipulating pickles to inject shellcode.
#2. Author
Marco Slaviero < marco(at)sensepost(dot)com >
#3. License, version & release date
License : GPL  
Version : v0.2  
Release Date : 2011/08/05

#4. Description
Anapickle performs two functions; it accepts, analyses and manipulates a supplied pickle or it can
produce Pickle shellcode as a standalone generator using a templated library. As an analyser, it includes
a simplified Pickle version 0 simulator that extracts a list of callables used by the pickle stream as well as
determines the position and type of all useful entities (strings, unicodes and ints) without subjecting the
pickle stream to a potentially dangerous loads() call (since loads() is the vulnerable method, we would
be remiss in simply piping any unknown pickle through a local loads() call). As a shellcode generator it
takes the name of a shellcode template and inserts user-supplied parameters such as filenames or shell
commands.
#5. Requirements
Python 2.3
#6. Additional Resources 
Sour Pickles - Presentation (http://www.sensepost.com/labs/conferences/2011/sour\_pickles)  
Sour Picklel - Shellcoding in Python’s serialisation format (http://www.sensepost.com/cms/resources/labs/tools/pentest/anapickle/BH\_US\_11\_Slaviero\_Sour\_Pickles\_WP.pdf)
