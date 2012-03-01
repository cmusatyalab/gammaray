default:
	@gcc stream_analyzer.c ../disk_analyzer/color.c qemu_tracer.c tokenizer.c -o stream_analyzer -Wall -Werror #-DNOCOLOR

test: default
	@./stream_analyzer /home/wolf/Dropbox/Projects/xray/sample/qemu_tinycore.raw.trace

clean:
	@rm stream_analyzer
