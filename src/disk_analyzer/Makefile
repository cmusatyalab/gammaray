default:
	@gcc disk_analyzer.c color.c ext2.c mbr.c -o disk_analyzer -Wall -Werror #-DNOCOLOR
	@gcc inode_explorer.c ext2.c color.c mbr.c -o inode_explorer -Wall -Werror
	@gcc data_block_explorer.c ext2.c color.c mbr.c -o data_block_explorer -Wall -Werror

test: default
	@./disk_analyzer /home/wolf/Dropbox/Projects/xray/sample/tinycore.raw 2> log#| less -R

bigtest: default
	@./disk_analyzer /home/wolf/sample_virtual_disks/tinycore_big.img

demo: default
	./disk_analyzer /home/wolf/Dropbox/Projects/xray/sample/tinycore.raw | \
	less -ru

clean:
	@rm disk_analyzer *.gch

inode_explorer: default
	./inode_explorer /home/wolf/Dropbox/Projects/xray/sample/tinycore.raw 

data_block_explorer: default
	./data_block_explorer /home/wolf/Dropbox/Projects/xray/sample/tinycore.raw
