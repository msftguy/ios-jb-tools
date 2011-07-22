
#@constants -----------------------------------
#.pool
.thumb
.pool
entry_point:
	adr	r2, data_start
.patchloop:
	ldr	r3, [r2]
        movs    r3, r3
        beq     .out
	ldr	r0, [r2, #4]
	str	r0, [r1, r3]
	add	r2, #8 
	b	.patchloop
.out:
	bx	lr

# put all constants here	
	.align  
	.ltorg
data_start:
	.word	0xDeadB34f
.end
