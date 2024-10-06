all: run
build:
	nasm -f bin -Ox -o tiny tiny.asm
link: build
	chmod +x tiny
run: link
	@ls -l tiny | awk '{print $$5}' | xargs -I {} echo "size: {} bytes"
	@./tiny
clean:
	rm tiny.o tiny