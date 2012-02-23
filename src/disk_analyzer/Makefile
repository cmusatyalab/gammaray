default:
	@gcc disk_analyzer.c color.c ext2.c -o disk_analyzer -Wall -Werror #-DNOCOLOR

test: default
	@./disk_analyzer /home/wolf/Dropbox/Projects/xray/sample/tinycore.raw

bigtest: default
	@./disk_analyzer /home/wolf/sample_virtual_disks/tinycore_big.img

demo: default
	./disk_analyzer /home/wolf/Dropbox/Projects/xray/sample/tinycore.raw | \
	less -ru

clean:
	@rm disk_analyzer *.gch
