default:
	@gcc disk_analyzer.c -o disk_analyzer -Wall -Werror

test: default
	@./disk_analyzer /home/wolf/Dropbox/Projects/xray/sample/tinycore.raw

clean:
	@rm disk_analyzer
