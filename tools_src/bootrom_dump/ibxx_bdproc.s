# On entry: r0->"Creating ramdisk at 0x%x of size 0x%x, from image at 0x%x"
# r1=rd_addr
# r2=rd_size
# r3=img_addr
#@constants -----------------------------------
#.pool
.thumb
.equ	bootrom_size, 0x10000
.equ	bootrom_addr, 0xBBBBADDD
.equ	test_patt, 0x1337Babe
.equ	pattern, 0xBaadF00d
.pool
entry_point:
	push	{r4-r7, lr}
	mov	r4, #0
	ldr 	r5, =pattern	
.patchloop:
        ldr	r0, [r1]
	cmp 	r0, r5
	bne	.ne
.eq:
	movs	r4, r4
	bne	.cont
	mov	r4, r1	
	b 	.cont	
.ne:
	movs 	r4, r4
	beq	.cont
	ldr	r0, =bootrom_size
	add	r0, r4
	cmp	r1, r0	
	bge	.copyout
.ne_out:
	mov	r4, #0	
.cont:
	add	r1, #4
	sub     r2, #4 
	cmp	r2, #0
	bgt	.patchloop
.out:
	pop	{r4-r7, pc}
.copyout:
	# r4: target addr
	# r1: src addr
	ldr	r1, =bootrom_addr 
	ldr	r2, =bootrom_size
	#ldr	r0, =test_patt
.copyloop:
	ldr	r0, [r1]
	add	r1, #4
	str	r0, [r4]
	add	r4, #4
	sub	r2, #4
	cmp	r2, #0
	bgt	.copyloop
	b	.out	
# put all constants here	
	.align  
	.ltorg
.end
