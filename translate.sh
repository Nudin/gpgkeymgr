#!/bin/bash

location="locale"
lang="de_DE"
langname="german"

if [ "$1" = "--locale" ] ; then
 sed --in-place schluesselwaerter.cpp --expression='s!/usr/share/locale!locale!'
 location="locale"
 shift
elif [ "$1" = "--install" ] ; then
 sed --in-place schluesselwaerter.cpp --expression='s!locale!/usr/share/locale!'
 location="/usr/share/locale"
 shift
else
 sed --in-place schluesselwaerter.cpp --expression='s!/usr/share/locale!locale!'
 location="locale"
fi
if [ "$1" = "de" ] ; then
	lang="de_DE"
	langname="german"
elif [ "$1" != "" ] ; then
	lang=$1
	read -p "Language-name: " langname
else
	read -p "Language-code (xx_XX): " lang
	read -p "Language-name: " langname
fi

xgettext --from-code=UTF-8 -d schluesselwaerter -s -o schluesselwaerter-new.pot schluesselwaerter.cpp
if [ -f ${langname}.po ] ; then
	msgmerge -s -U ${langname}.po schluesselwaerter-new.pot
	mv schluesselwaerter-new.pot schluesselwaerter.pot
else
	mv schluesselwaerter-new.pot schluesselwaerter.pot
	msginit -l ${lang} -o ${langname}.po -i schluesselwaerter.pot
	sed --in-place ${langname}.po --expression="s/PACKAGE VERSION/${langname}/"
fi

echo "You can now edit the file ${langname}.po - when finished press any key to continue."
read

msgfmt -c -v -o schluesselwaerter.mo ${langname}.po
mkdir -p ${location}/${lang}/LC_MESSAGES
mv schluesselwaerter.mo ${location}/${lang}/LC_MESSAGES
rm *.po~
echo "Finished. You may compile now."
