.PHONY: all

all: bin/docker-authz-mruby

bin/docker-authz-mruby: vendor vendor/github.com/mitchellh/go-mruby/libmruby.a
	go build -o bin/docker-authz-mruby .

vendor:
	dep ensure

vendor/github.com/mitchellh/go-mruby/libmruby.a:
	cd vendor/github.com/mitchellh/go-mruby && MRUBY_CONFIG=../../../../../../mruby_config.rb ${MAKE}
