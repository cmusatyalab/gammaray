default:
	@gcc stream_analyzer.c ../disk_analyzer/color.c -o stream_analyzer -Wall -Werror #-DNOCOLOR

test: default
	@./stream_analyzer /home/wolf/Dropbox/Projects/xray/sample/tinycore.index

clean:
	@rm stream_analyzer
