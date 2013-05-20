NAME	= gpgkeymgr
#VERSION	= 0.4

SHELL	:= /bin/bash
SRC	= src/$(NAME).cpp src/vectorutil.cpp src/stringutil.cpp src/copyfile.cpp
BINDIR	= /usr/bin
FLAGS	= -D_FILE_OFFSET_BITS=64 #-DVERS=\"$(VERSION)\"
LIBPATH	= -L/usr/include/ -L/usr/include/gpgme/ -L/usr/local/include/ -L/usr/include/gpgme/
LIBS	= -lgpgme
LOCAL	= /usr/share/locale/
MAN	= /usr/share/man/

compile: $(SRC)
	g++ $(SRC) $(FLAGS) $(LIBPATH) $(LIBS) -o $(NAME)

installall: install installtranslations installmanpagetranslations

install: compile manpages/$(NAME).1
	cp $(NAME) $(BINDIR)
	cp manpages/$(NAME).1 $(MAN)man1/
	chmod +r $(MAN)man1/$(NAME).1

clean:
	if [ -f $(NAME) ]; then rm $(NAME); fi
	if [ -f $(NAME).pot ]; then rm $(NAME).pot; fi
	if [ -f $(NAME)-$(VERSION).tar.gz ]; then rm $(NAME)-$(VERSION).tar.gz*; fi

portable: $(SRC)
	g++ $(SRC) $(FLAGS) $(LIBPATH) -DLOCAL $(LIBS) -o $(NAME)
	mkdir locale
	for i in translations/*.mo; do\
	  mkdir locale/$${i:23:5}/LC_MESSAGES;\
	  cp $$i locale/$${i:23:5}/LC_MESSAGES/;\
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
	for i in $^; do mkdir -p $(LOCAL)$${i:23:5}/LC_MESSAGES/; cp $$i $(LOCAL)$${i:23:5}/LC_MESSAGES/$(NAME).mo; chmod +r $(LOCAL)$${i:23:5}/LC_MESSAGES/$(NAME).mo; done

#will install all translation of the manpage
installmanpagetranslations: $(wildcard manpages/$(NAME)-*.1)
	for i in $^; do cp $$i $(MAN)$${i:19:2}/man1/$(NAME).1; chmod +r $(MAN)$${i:19:2}/man1/$(NAME).1; done

### for developers ##

tarball: compile
	mkdir ../$(NAME)-$(VERSION)
	cp -r * ../$(NAME)-$(VERSION)
	tar cvzf $(NAME)-$(VERSION).tar.gz ../$(NAME)-$(VERSION)
	sha256sum $(NAME)-$(VERSION).tar.gz > $(NAME)-$(VERSION).tar.gz.sha256
	gpg --detach-sign $(NAME)-$(VERSION).tar.gz
	rm -rf ../$(NAME)-$(VERSION)
