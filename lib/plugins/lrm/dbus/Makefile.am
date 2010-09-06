if UPSTART
BINDINGS=Upstart_Instance.h \
	Upstart_Job.h \
	Upstart.h

all-local:
	for header in $(BINDINGS); do \
		input=com.ubuntu.`echo $$header | sed 's/\.h//' | tr _ .`.xml; \
		$(DBUS_BINDING_TOOL) --mode=glib-client $$input > $$header; \
	done

clean-local:
	rm -f $(BINDINGS)

EXTRA_DIST = *.xml
endif
