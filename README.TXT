Wii NAND Extractor

Current build: 0.1.3
                      Frozen (working on new project with read/write).
                      New development for bug fixes only.
                      Report any bugs to tooparannoyed@gmail.com

 - Allows you to browse and extract Wii NAND dumps, including BootMii and 
   any other "standard" Wii NAND dump (ECC and non-ECC).
 - Single file or selected directory extraction supported.
 - Displays total space used, total files, and each individual file mode, 
   attribute, UID, GID, and size.
 - Looks for BootMii key.bin in the same directory as NAND file.

Instructions:
  * Open a dump file.
  * Use the "Extract All" menu option, or right click on a file/directory and
    select "Extract".

  
Written in C#, source code included.

Copyright 2009 Ben Wilson / parannoyed
http://sites.google.com/site/parannoyedwii/

Thanks to...
  Wiibrew.org http://www.wiibrew.org/
  Segher's Wii.git http://git.infradead.org/?p=users/segher/wii.git
  BootMii http://bootmii.org/
  Crystal Project http://www.everaldo.com/crystal/ (GPL icon set)

-------------------------------------------------------------------------------

CHANGELOG
  20090930: 0.1.3  -  non-ECC dump support, file details, menu icons.
    - Sep 23 2009, had a baby boy, Liam Elijah: 8lb 4oz, 19.75"
    - Added support for non-ECC dumps.
    - Viewer displays additional file and NAND details.
    - Improved exception handling and other misc improvements.
    - Filenames containing ":" are replaced with "-" (ie. HP:OOTP == HP-OOTP).
    - Crystal Project icons, needed some color.

  20090914: 0.1.2  -  Updated for BootMii b3 and any ECC dump.
    - Supports extraction of any full (with ECC) Wii NAND dump .
    - Now looks for BootMii keys.bin in the same directory as NAND file.
    - Allows manual entry and saving of NAND key.

  20090903: 0.1.1  -  Initial release.
    - Only supports BootMii b1 and b2.

