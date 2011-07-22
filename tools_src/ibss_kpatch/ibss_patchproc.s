
#@constants -----------------------------------
#.pool
.thumb
.pool
entry_point:
	ldr	r2, =0xFeedFace
.searchloop:
	sub r1, #1
.ifdef ARMV7
	bfc r1, #0, #12
.else
        ldr r0, =0xFFFFf000
        and r1, r0
.endif
	ldr r0, [r1]
	cmp r0, r2
	bne .searchloop

	adr	r2, data_start
.patchloop:
	ldr	r3, [r2]
.ifdef ARMV7
	cbz	r3, .out
.else
        movs    r3, r3
        beq     .out
.endif
	ldr	r0, [r2, #4]
	str	r0, [r1, r3]
	add	r2, #8 
	b	.patchloop
.out:
	bx	lr

# put all constants here	
	.ltorg
data_start:
	.word	0xDeadB33f
.end
