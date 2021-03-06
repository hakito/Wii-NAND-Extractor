# CHANGELOG

## WIP: 1.2.0 - Multi-platform

* Exception based error handling
* Split NAND logic into separate file
* Multi-platform Avalonia GUI

## 20210103: 1.1.1 - Export single file

* Fix exporting a single file
* Extend copyright in about dialog

## 20201228: 1.1 - Fork with usability improvements

* Export folder can be chosen upon export
* NAND filepath and export folder can be stored in settings.
  The NAND file from the app settings is automatically loaded.
* DEBUG builds automatically persist the last NAND file and export folder

## 20090930: 0.1.3  -  non-ECC dump support, file details, menu icons

* Sep 23 2009, had a baby boy, Liam Elijah: 8lb 4oz, 19.75"
* Added support for non-ECC dumps.
* Viewer displays additional file and NAND details.
* Improved exception handling and other misc improvements.
* Filenames containing ":" are replaced with "-" (ie. HP:OOTP == HP-OOTP).
* Crystal Project icons, needed some color.

## 20090914: 0.1.2  -  Updated for BootMii b3 and any ECC dump

* Supports extraction of any full (with ECC) Wii NAND dump .
* Now looks for BootMii keys.bin in the same directory as NAND file.
* Allows manual entry and saving of NAND key.

## 20090903: 0.1.1  -  Initial release

* Only supports BootMii b1 and b2.
