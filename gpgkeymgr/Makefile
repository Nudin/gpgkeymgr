NAME=gpgkeymgr
SRC=$(NAME).cpp

compile: $(SRC)
	g++ $(SRC) -lgpgme -o $(NAME)

installall: install installtranslations

install: compile $(NAME).1
	cp $(NAME) /usr/bin
	cp $(NAME).1 /usr/share/man/man1/

clean:
	rm $(NAME)
	rm a.out $(NAME).pot

portable: $(SRC)
	sed --in-place $(SRC) --expression='s!textpath="/usr/share/locale"!textpath="locale"!'
	g++ $(SRC) -lgpgme -o $(NAME)
	for i in translations/*.mo; do\
	  mkdir locale/$${i:31:5}/LC_MESSAGES;\
	  cp $$i locale/$${i:31:5}/LC_MESSAGES/;\
	done

### i18n ###

# To create a new translation-file 
newtranslation: $(SRC) translate.sh
	read -p "Language-code (xx_XX): " lang;\
	read -p "Language-name: " langname;\
	po=translations/$(NAME)-$${lang}.po;\
	xgettext --from-code=UTF-8 -k_ -d $(NAME) -s -o $(NAME).pot $(SRC);\
	msginit -l $${lang} -o $$po -i $(NAME).pot;\
	sed --in-place $$po --expression="s/PACKAGE VERSION/$${langname}/"
	echo "Run 'make finishtranslations' if you are finished with translating."

# To update translation-files
updatetranslations: $(wildcard translations/*.po)
	xgettext --from-code=UTF-8 -k_ -d $(NAME) -s -o $(NAME).pot $(SRC)
	for i in $^; do msgmerge -s -U $$i $(NAME).pot; done

# will create .mo files of all .po files
finishtranslations: 
	cd translations; for i in *.po ; do msgfmt -c -v -o $${i/.po/.mo} $$i; done

# will install all translations
installtranslations: $(wildcard translations/$(NAME)-*.mo)
	for i in $^; do cp $$i /usr/share/locale/$${i:31:5}/LC_MESSAGES/; done

