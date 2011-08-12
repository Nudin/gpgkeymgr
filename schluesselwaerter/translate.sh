#!/bin/bash
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Lesser General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Lesser General Public License for more details.

#    You should have received a copy of the GNU Lesser General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

location=""
lang="de_DE"
langname="german"
finish=0

while getopts "hfli" optionName; do
case "$optionName" in
f) 	finish=1;;
l)	sed --in-place schluesselwaerter.cpp --expression='s!textpath="/usr/share/locale"!textpath="locale"!'
	location="locale";;
i)	sed --in-place schluesselwaerter.cpp --expression='s!textpath="locale"!textpath="/usr/share/locale"!'
	location="/usr/share/locale";;
h)	echo -e "./translate [-f] [-l|-i] lang_LANG";exit;;
[?]) echo "./translate [-f] [-l|-i]";exit;;
esac
done
shift $(($OPTIND-1))
echo $@

if [ "$1" = "de" -o "$1" = "de_DE" ] ; then
	lang="de_DE"
	langname="german"
elif [ "$1" != "" ] ; then
	lang=$1
	read -p "Language-name: " langname
else
	read -p "Language-code (xx_XX): " lang
	read -p "Language-name: " langname
fi

if [ "$location" = "" ] ; then	# Default Location
	sed --in-place schluesselwaerter.cpp --expression='s!/textpath="/usr/share/locale"!textpath="locale"!'
	location="locale"
fi

if [ $finish -eq 0 ] ; then	# Create po-file
   xgettext --from-code=UTF-8 -k_ -d schluesselwaerter -s -o schluesselwaerter-new.pot schluesselwaerter.cpp
   if [ -f ${langname}.po ] ; then	# If po-file already exists, update.
	msgmerge -s -U ${langname}.po schluesselwaerter-new.pot
	mv schluesselwaerter-new.pot schluesselwaerter.pot
   else
	mv schluesselwaerter-new.pot schluesselwaerter.pot
	msginit -l ${lang} -o ${langname}.po -i schluesselwaerter.pot
	sed --in-place ${langname}.po --expression="s/PACKAGE VERSION/${langname}/"
   fi

   echo "You can now edit the file ${langname}.po"
   echo "Run ./translate --finish --<mode>"
else	# Create .mo out of .po and put it to wished palce
   msgfmt -c -v -o schluesselwaerter.mo ${langname}.po
   mkdir -p ${location}/${lang}/LC_MESSAGES
   mv schluesselwaerter.mo ${location}/${lang}/LC_MESSAGES
   mkdir translations 2> /dev/null
   mv schluesselwaerter.mo translations/schluesselwaerter-${lang}.mo
   rm *.po~ *pot 2> /dev/null
   echo "Finished. You may compile now."
fi
