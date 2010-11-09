
@constants -----------------------------------
.pool

entry_point:
	ADR	R2, data_start
.loop:
	LDR	R3, [R2]
	CBZ	R3, .out
	LDR	R0, [R2, #4]
	STR	R0, [R1, R3]
	ADD	R2, #8 
	B	.loop
.out:
	BX	LR
data_start:
	.word	0xDEADF00D
.end
