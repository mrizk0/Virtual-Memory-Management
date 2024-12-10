/* vim: tabstop=4 shiftwidth=4 noexpandtab
 */

OUTPUT_FORMAT("elf64-x86-64", "elf64-x86-64",
              "elf64-x86-64")

ENTRY(start)

SECTIONS
{
	/* put the userspace programs in the "high half" */
	. = 0xffff800000000000;

	/* Put all "text" like things in the same area */
	.text : {
		/* Put the `start` function at the start so it is the first code executed */
		*(.init) 
		*(.text*)
	}

	/* Put all "data" like sections in the same area */
	.data : {
    *(.rodata)
		*(.bss)
		*(.data)
	}
}

