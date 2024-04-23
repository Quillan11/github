	#
        # code to switch between user and kernel space.
        #
        # this code is mapped at the same virtual address
        # (TRAMPOLINE) in user and kernel space so that
        # it continues to work when it switches page tables.
	#
	# kernel.ld causes this to be aligned
        # to a page boundary.
        #
	.section trampsec
.globl trampoline
trampoline:
.align 4
.globl uservec
uservec:    
	#
        # trap.c sets stvec to point here, so
        # traps from user space start here,
        # in supervisor mode, but with a
        # user page table.
        #
        # sscratch points to where the process's p->trapframe is
        # mapped into user space, at TRAPFRAME.
        #
        
		# swap a0 and sscratch
        # so that a0 is TRAPFRAME
        # 译：交换a0和sscratch的值
        # 所以a0现在的值指向trapframe
        # csrrw的用法：csrrw rd, csr, rs1
        # csrrw的作用：t = CSRs[csr], CSRs[csr] = x[rs1], x[rd] = t
        # 下面这条指令的作用即：t = sscratch, sscratch = a0, a0 = t
        # 即交换了二者的值，既暂存了a0在sscratch中，又使得a0指向了trapframe

        csrrw a0, sscratch, a0

        # save the user registers in TRAPFRAME
        sd ra, 40(a0)
        sd sp, 48(a0)
        sd gp, 56(a0)
        sd tp, 64(a0)
        sd t0, 72(a0)
        sd t1, 80(a0)
        sd t2, 88(a0)
        sd s0, 96(a0)
        sd s1, 104(a0)
        sd a1, 120(a0)
        sd a2, 128(a0)
        sd a3, 136(a0)
        sd a4, 144(a0)
        sd a5, 152(a0)
        sd a6, 160(a0)
        sd a7, 168(a0)
        sd s2, 176(a0)
        sd s3, 184(a0)
        sd s4, 192(a0)
        sd s5, 200(a0)
        sd s6, 208(a0)
        sd s7, 216(a0)
        sd s8, 224(a0)
        sd s9, 232(a0)
        sd s10, 240(a0)
        sd s11, 248(a0)
        sd t3, 256(a0)
        sd t4, 264(a0)
        sd t5, 272(a0)
        sd t6, 280(a0)

	# save the user a0 in p->trapframe->a0
        csrr t0, sscratch
        sd t0, 112(a0)

        #至此，完成了所有寄存器信息的保存

        # restore kernel stack pointer from p->trapframe->kernel_sp
        # 恢复对应进程的内核栈指针      
        ld sp, 8(a0)

        # make tp hold the current hartid, from p->trapframe->kernel_hartid
        # 将trapframe中存放的cpu的id号放入tp寄存器
        # hartid是RISC-V给每个CPU的一个ID号，内核态下必须保存在tp寄存器中
        ld tp, 32(a0)

        # load the address of usertrap(), p->trapframe->kernel_trap
        # 将p->trapframe->kernel_trap的地址放入t0寄存器，准备跳入
        ld t0, 16(a0)

        # restore kernel page table from p->trapframe->kernel_satp
        # 从p->trapframe的kernel_satp中恢复内核页表
        ld t1, 0(a0)
        csrw satp, t1

        # 清空快表TLB
        sfence.vma zero, zero

        # <自此：地址空间已经从用户地址空间切换进入内核地址空间>
        # 所有地址翻译都将通过内核页表进行，但是原有地址翻译完全被打破
        # 但是因为trampoline.S的代码映射在内核和用户空间中保持一致
        # 所以代码得以连续不断地继续执行(PC的连续性得以保持)

        # a0 is no longer valid, since the kernel page
        # table does not specially map p->tf.
        # 译：a0此时不再有效，因为内核地址空间并没有用户的trapframe的映射

        # jump to usertrap(), which does not return
        # 跳转进usertrap的地址，本操作不会返回
        jr t0

.globl userret
userret:
        # userret(TRAPFRAME, pagetable)
        # switch from kernel to user.
        # usertrapret() calls here.
        # a0: TRAPFRAME, in user page table.
        # a1: user page table, for satp.

        # switch to the user page table.
        csrw satp, a1
        sfence.vma zero, zero

        # put the saved user a0 in sscratch, so we
        # can swap it with our a0 (TRAPFRAME) in the last step.
        ld t0, 112(a0)
        csrw sscratch, t0

        # restore all but a0 from TRAPFRAME
        ld ra, 40(a0)
        ld sp, 48(a0)
        ld gp, 56(a0)
        ld tp, 64(a0)
        ld t0, 72(a0)
        ld t1, 80(a0)
        ld t2, 88(a0)
        ld s0, 96(a0)
        ld s1, 104(a0)
        ld a1, 120(a0)
        ld a2, 128(a0)
        ld a3, 136(a0)
        ld a4, 144(a0)
        ld a5, 152(a0)
        ld a6, 160(a0)
        ld a7, 168(a0)
        ld s2, 176(a0)
        ld s3, 184(a0)
        ld s4, 192(a0)
        ld s5, 200(a0)
        ld s6, 208(a0)
        ld s7, 216(a0)
        ld s8, 224(a0)
        ld s9, 232(a0)
        ld s10, 240(a0)
        ld s11, 248(a0)
        ld t3, 256(a0)
        ld t4, 264(a0)
        ld t5, 272(a0)
        ld t6, 280(a0)

	# restore user a0, and save TRAPFRAME in sscratch
        csrrw a0, sscratch, a0
        
        # return to user mode and user pc.
        # usertrapret() set up sstatus and sepc.
        sret
