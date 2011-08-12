LANG=de_DE
LANGFILE=translations/schluesselwaerter-$(LANG).mo

compile: schluesselwaerter.cpp
	g++ schluesselwaerter.cpp -lgpgme -o schluesselwaerter

install: compile $(LANGFILE)
	cp schluesselwaerter /usr/bin
	cp $(LANGFILE) /usr/share/locale/$(LANG)/LC_MESSAGES/

clean: schluesselwaerter a.out german.mo
	rm schluesselwaerter
	rm a.out

portable: schluesselwaerter.cpp
	sed --in-place schluesselwaerter.cpp --expression='s!textpath="/usr/share/locale"!textpath="locale"!'
	g++ schluesselwaerter.cpp -lgpgme -o schluesselwaerter
	mkdir locale/$(LANG)/LC_MESSAGES
	cp $(LANGFILE) locale/$(LANG)/LC_MESSAGES/


### i18n ###

newtranslation: schluesselwaerter.cpp translate.sh
	./translate.sh -i
	echo "Run 'make finishtranslation' if you are finished with translating."

# Note quite good
finishtranslation: 
	./translate.sh -f 

# will install all translations
installtranslations: $(wildcard translations/schluesselwaerter-*.mo)
	for i in $^; do cp $$i /usr/share/locale/$${i:31:5}/LC_MESSAGES/; done
