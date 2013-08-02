REBAR = rebar

.PHONY: compile
compile:
	$(REBAR) compile

.PHONY: clean
clean:
	$(REBAR) clean
